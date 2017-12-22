// Copyright (C) 2016-2017 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::u64;
use std::mem;
use std::sync::Mutex;
use url::Url;

use glib;
use gst;
use gst::prelude::*;
use gst_base;
use gst_base::prelude::*;

use gst_plugin::object::*;
use gst_plugin::properties::*;
use gst_plugin::element::*;
use gst_plugin::base_src::*;
use gst_plugin::uri_handler::*;
use gst_plugin::error::*;

pub use gst_plugin::base_src::BaseSrc;

static PROPERTIES: [Property; 1] = [
    Property::String(
        "uri",
        "URI",
        "URI to read from",
        None,
        PropertyMutability::ReadWrite,
    ),
];

//#[derive(Debug)]
enum StreamingState {
    Stopped,
    Ready {
        command_sender: io_thread::CommandSender,
        start: u64,
        stop: Option<u64>,
    },
    Started {
        command_sender: io_thread::CommandSender,
        // TODO: Store request::Method: Either HEAD or GET
        uri: Arc<Url>,
        start: u64,
        stop: Option<u64>,
        parsed_headers: Option<Arc<ParsedHeaders>>,
        request_state: RequestState,
    },
}

enum RequestState {
    None,
    Initialized { request_receiver: io_thread::ItemReceiver<io_thread::RequestItem>, expected_position: u64 },
    WaitingForHeaders { pending_headers: Arc<PendingHeaders> },
    IdleStreaming { request_receiver: io_thread::ItemReceiver<io_thread::RequestItem>, position: u64 },
    ActiveStreaming,
}

struct PendingHeaders {
    headers: Mutex<(Option<Arc<ParsedHeaders>>, bool)>,
    cond: Condvar,
}

impl PendingHeaders {
    fn new() -> (Arc<PendingHeaders>, PendingHeadersSetter) {
        let pending_headers = Arc::new(PendingHeaders {
            headers: Mutex::new((None, false)),
            cond: Condvar::new(),
        });

        (pending_headers.clone(), PendingHeadersSetter(pending_headers))
    }

    fn get(&self) -> Option<Arc<ParsedHeaders>> {
        let pending_headers = self.headers.lock().unwrap();

        while let (None, false) = *pending_headers {
            self.cond.wait(pending_headers);
        }

        match *pending_headers {
            (None, true) => None,
            (Some(ref headers), _) => Some(headers.clone()),
            _ => unreachable!(),
        }
    }
}

struct PendingHeadersSetter(Arc<PendingHeaders>);

impl PendingHeadersSetter {
    fn set(self, headers: Arc<ParsedHeaders>) {
        let mut pending_headers = self.0.headers.lock().unwrap();
        pending_headers = (Some(headers), false);
        self.0.cond.notify_all();
    }
}

impl Drop for PendingHeadersSetter {
    fn drop(&mut self) {
        let mut pending_headers = self.0.headers.lock().unwrap();
        if let (None, ref mut cancelled) = *pending_headers {
            *cancelled = true;
            self.0.cond.notify_all();
        }
    }
}

#[derive(Clone)]
struct Settings {
    uri: Option<Arc<Url>>,
}

#[derive(Debug)]
struct ParsedHeaders {
    seekable: bool,
    size: Option<u64>,
}

//#[derive(Debug)]
pub struct HttpSrc {
    streaming_state: Mutex<StreamingState>,
    settings: Mutex<Settings>,
    closer: Mutex<Option<io_thread::ItemChannelCloser<io_thread::RequestItem>>>,
    cat: gst::DebugCategory,
}

impl HttpSrc {
    pub fn new(_src: &BaseSrc) -> Self {
        HttpSrc {
            streaming_state: Mutex::new(StreamingState::Stopped),
            settings: Mutex::new(Settings { uri: None }),
            closer: Mutex::new(None),
            request_state: Mutex::new(RequestState::None),
            cat: gst::DebugCategory::new(
                "rshttpsrc",
                gst::DebugColorFlags::empty(),
                "Rust HTTP source",
            ),
        }
    }

    fn class_init(klass: &mut BaseSrcClass) {
        klass.set_metadata(
            "HTTP/HTTPS Source",
            "Source/Network",
            "Reads HTTP/HTTPS streams",
            "Sebastian Dröge <sebastian@centricular.com>",
        );

        let caps = gst::Caps::new_any();
        let pad_template = gst::PadTemplate::new(
            "src",
            gst::PadDirection::Src,
            gst::PadPresence::Always,
            &caps,
        );
        klass.add_pad_template(pad_template);

        klass.install_properties(&PROPERTIES);
    }

    fn init(element: &BaseSrc) -> Box<BaseSrcImpl<BaseSrc>> {
        let imp = Self::new(element);
        Box::new(imp)
    }

    fn get_uri(&self, _element: &glib::Object) -> Option<String> {
        let settings = &self.settings.lock().unwrap();
        settings.uri.as_ref().map(|uri| String::from(uri.as_str()))
    }

    fn set_uri(&self, element: &glib::Object, uri_str: Option<String>) -> Result<(), glib::Error> {
        let src = element.clone().dynamic_cast::<BaseSrc>().unwrap();

        let settings = &mut self.settings.lock().unwrap();

        gst_debug!(self.cat, obj: &src, "Setting URI {:?}", uri_str);

        settings.uri = None;

        if let Some(uri_str) = uri_str {
            match Url::parse(uri_str.as_str()) {
                Ok(uri) => {
                    if uri.scheme() != "http" && uri.scheme() != "https" {
                        return Err(
                            UriError::new(
                                gst::URIError::UnsupportedProtocol,
                                format!("Unsupported URI '{}'", uri.as_str()),
                            ).into_error(),
                        );
                    }

                    settings.uri = Some(Arc::new(uri));
                    Ok(())
                }
                Err(err) => Err(
                    UriError::new(
                        gst::URIError::BadUri,
                        format!("Failed to parse URI '{}': {}", uri_str, err),
                    ).into_error(),
                ),
            }
        } else {
            Ok(())
        }
    }

    fn do_request(&self, src: &BaseSrc, command_sender: &io_thread::CommandSender, uri: Url, start: u64, stop: Option<u64>) {
        gst_debug!(self.cat, obj: src, "Doing new request for '{}' [{:?}-{:?}]", uri, start, stop);

        // Cancel any previous request
        {
            let mut closer = self.closer.lock().unwrap();
            closer.as_ref().map(|c| c.close());
            *closer = None;
        }
        let mut request_state = self.request_state.lock().unwrap();

        // Do not need to reset the parsed headers here: It is only possible to change it if we go
        // back to READY state, in which case we will forget the parsed headers

        let (mut request_receiver, request_closer) = command_sender.request(uri, start, stop);
        *self.closer.lock().unwrap() = Some(request_closer);
        *request_state = RequestState::Initialized { request_receiver, expected_position: start};
    }

    fn ensure_headers(&self) -> Option<Arc<ParsedHeaders>> {
        use either::{Left, Right, Either};

        let next = {
            let streaming_state = self.streaming_state.lock().unwrap();
            // First of all check if we are in the right state, and
            // if we are whether we already have the headers anyway
            match *streaming_state {
                StreamingState::Started { ref parsed_headers, .. } => {
                    if let Some(ref parsed_headers) = parsed_headers {
                        return Some(parsed_headers.clone());
                    }
                },
                _ => return None
            }

            let next = match *streaming_state.request_state {
                RequestState::None |
                RequestState::IdleStreaming { ..} |
                RequestState::ActiveStreaming => {
                    // This can't happen: Either we're not in Started anymore then,
                    // or we should've received headers already
                    return None;
                },
                RequestState::Initialized { .. } => {
                    let (pending_headers, pending_headers_setter) = PendingHeaders::new();
                    Left((RequestState::WaitingForHeaders { pending_headers }, pending_headers_setter))
                },
                RequestState::WaitingForHeaders { ref pending_headers } => {
                    Right(pending_headers.clone())
                },
            };

            match next {
                Left((next_state, pending_headers_setter)) => {
                    let old_state = mem::replace(&mut streaming_state.request_state, next_state);
                    Left((old_state, pending_headers_setter))
                },
                Right(pending_headers) => {
                    Right(pending_headers)
                }
            }
        };

        // At this point, nothing is locked and we will either just wait for headers
        // to be read by someone else, or do so ourselves, parse them and signal all waiters
        match next {
            Left((RequestState::Initialized { request_receiver, expected_position }), pending_headers_setter) => {
                while let Some(item) = request_receiver.recv() {
                    RequestItem::Headers(headers) => {
                        // TODO parse headers
                        pending_headers.set(parsed_headers.clone());
                        Some(parsed_headers)
                    },
                    RequestItem::Error(err) => {
                        // TODO we will never get headers
                    },
                    RequestItem::Eos => {
                        // TODO we will never get headers
                    },
                    _ => {
                        // TODO this is wrong
                    },
                }
            },
            Right(pending_headers) => {
                pending_headers.get()
            }
        }
    }

    fn parse_headers(&self, src: &BaseSrc, expected_position: u64, headers: &Headers) -> Result<ParsedHeaders, ErrorMessage> {
        unimplemented!()
    }
}

impl ObjectImpl<BaseSrc> for HttpSrc {
    fn set_property(&self, obj: &glib::Object, id: u32, value: &glib::Value) {
        let prop = &PROPERTIES[id as usize];

        match *prop {
            Property::String("uri", ..) => {
                let _ = self.set_uri(obj, value.get());
            }
            _ => unimplemented!(),
        }
    }

    fn get_property(&self, obj: &glib::Object, id: u32) -> Result<glib::Value, ()> {
        let prop = &PROPERTIES[id as usize];

        match *prop {
            Property::String("uri", ..) => Ok(self.get_uri(obj).to_value()),
            _ => unimplemented!(),
        }
    }
}

impl ElementImpl<BaseSrc> for HttpSrc {
    fn change_state(
        &self,
        src: &BaseSrc,
        transition: gst::StateChange,
    ) -> gst::StateChangeReturn {
        gst_debug!(self.cat, obj: src, "Changing state {:?}", transition);

        match transition {
            gst::StateChange::ReadyToNull => {
                {
                    let mut closer = self.closer.lock().unwrap();
                    closer.as_ref().map(|c| c.close());
                    *closer = None;
                }
                *self.request_state.lock().unwrap() = RequestState::None;
                *self.streaming_state.lock().unwrap() = StreamingState::Stopped;
            }
            _ => (),
        }

        let ret = src.parent_change_state(transition);
        if ret == gst::StateChangeReturn::Failure {
            return ret;
        }

        match transition {
            gst::StateChange::NullToReady => {
                *self.streaming_state.lock().unwrap() = StreamingState::Ready {
                    command_sender: io_thread::get_command_sender(),
                    start: 0,
                    stop: None,
                };
            }
            _ => (),
        }

        ret
    }
}

impl BaseSrcImpl<BaseSrc> for HttpSrc {
    fn start(&self, src: &BaseSrc) -> bool {
        gst_debug!(self.cat, obj: src, "Starting");

        let settings = self.settings.lock().unwrap().clone();
        let uri = match settings.uri {
            None => {
                gst_error!(self.cat, obj: src, "No URI given");
                gst_element_error!(src, gst::ResourceError::OpenRead, ["No URI given"]);
                return false;
            }
            Some(ref uri) => uri.clone(),
        };

        // Keep streaming state locked until we did our request
        //
        // This ensures that whenever we're in Started, there is also the current request available
        // and we can wait for headers
        //
        // Note: NEVER lock request/query_state before streaming_state, only the other way around
        // or without locking the streaming_state
        let mut streaming_state = self.streaming_state.lock().unwrap();
        let (command_sender, start, stop) = match *streaming_state {
            StreamingState::Started { .. } => {
                gst_element_error!(src, gst::LibraryError::Failed, ["Already started"]);
                return false;
            },
            StreamingState::Ready { ref command_sender, start, stop } => {
                (command_sender.clone(),
                start,
                stop,
                )
            },
            StreamingState::Stopped => {
                gst_element_error!(src, gst::LibraryError::Failed, ["Not ready yet"]);
                return false;
            }
        };

        self.do_request(src, &command_sender, (*uri).clone(), start, stop);

        *streaming_state = StreamingState::Started { command_sender, uri, start, stop, parsed_headers: None };

        true
    }

    fn stop(&self, src: &BaseSrc) -> bool {
        gst_debug!(self.cat, obj: src, "Stopping");

        let mut streaming_state = self.streaming_state.lock().unwrap();
        let (command_sender, start, stop) = match *streaming_state {
            StreamingState::Started { ref command_sender, start, stop, .. } |
            StreamingState::Ready { ref command_sender, start, stop } => {
                (command_sender.clone(),
                start,
                stop,
                )
            },
            StreamingState::Stopped => {
                warning_msg!(gst::LibraryError::Failed, ["Not ready yet"]).post(src);
                return true;
            }
        };

        *streaming_state = StreamingState::Ready { command_sender, start, stop };

        let mut closer = self.closer.lock().unwrap();
        closer.as_ref().map(|c| c.close());
        *closer = None;

        *self.request_state.lock().unwrap() = RequestState::None;

        true
    }

    fn query(&self, src: &BaseSrc, query: &mut gst::QueryRef) -> bool {
        use gst::QueryView;

        match query.view_mut() {
            QueryView::Scheduling(ref mut q) => {
                q.set(
                    gst::SchedulingFlags::SEQUENTIAL | gst::SchedulingFlags::BANDWIDTH_LIMITED,
                    1,
                    -1,
                    0,
                );
                q.add_scheduling_modes(&[gst::PadMode::Push]);
                return true;
            }
            _ => (),
        }

        BaseSrcBase::parent_query(src, query)
    }

    fn create(
        &self,
        src: &BaseSrc,
        offset: u64,
        _length: u32,
    ) -> Result<gst::Buffer, gst::FlowReturn> {
        let cat = self.cat;

        // We only ever lock the request here, not the streaming_state
        //
        // If there is a request, we block on it until an item is received or we're flushing
        let mut request = {
            let mut request_state = self.request_state.lock().unwrap();
            let new_request = match request {
                RequestState::None => {
                    gst_element_error!(src, gst::LibraryError::Failed, ["No request yet"]);
                    return Err(gst::FlowReturn::Error);
                },
                RequestState::Initialized { .. } => {
                    gst_debug!(self.cat, obj: src, "Waiting for headers");
                    Some(RequestState::WaitingForHeaders {
                        headers_slot: Arc::new(Mutex::new(None), Condvar::new())
                    })
                },
                RequestState::WaitingForHeaders {
                    // TODO need to wait now, someone else is blocking on headers
                    None
                },
                RequestState::IdleStreaming { .. } => {
                    Some(RequestState::ActiveStreaming)
                }
                RequestState::ActiveStreaming => {
                    unreachable!()
                }
            };

            
        };

        if *position != offset {
            gst_element_error!(src,
                gst::ResourceError::Seek,
                ["Got unexpected offset {}, expected {}", offset, *position]
            );
            return Err(gst::FlowReturn::Error);
        }

        while let Some(item) = request_receiver.recv() {
            io_thread::RequestItem::Error(err) => {
                // TODO: Proper error distinction
                gst_element_error!(src,
                    gst::ResourceError::Read,
                    ["Got error: {}", err]
                );
                return Err(gst::FlowReturn::Error);
            }
            io_thread::RequestItem::Headers(headers) => {
                gst_debug!(self.cat, obj: src, "Got headers {:?}", headers);
                // TODO parse headers and put into QueryState
                unimplemented!();
                // and continue
            }
            io_thread::RequestItem::Chunk(chunk) => {
                gst_debug!(self.cat, obj: src, "Got chunk of {} bytes at position {}", chunk.len(), *position);

                let size = chunk.len();
                let buffer = gst::Buffer::from_slice(chunk).unwrap();
                *position += size as u64;

                return Ok(buffer);
            }
            io_thread::RequestItem::Eos => {
                gst_debug!(self.cat, obj: src, "Got EOS at position {}", *position);
                return Err(gst::FlowReturn::Eos);
            }
        };

        // We only ever go out of the loop if the receiver is flushed,
        // otherwise we return a result directly from inside the loop
        gst_debug!(self.cat, obj: src, "Flushing");
        Err(gst::FlowReturn::Flushing)
    }

    fn unlock(&self, _src: &BaseSrc) -> bool {
        // This unlocks the receiver, if something blocks on it in create(),
        // do_seek(), is_seekable() or get_size()
        let closer = self.closer.lock().unwrap();
        closer.as_ref().map(|c| c.close());

        true
    }

    fn do_seek(&self, src: &BaseSrc, segment: &mut gst::Segment) -> bool {
        // First check if we *know* that we're not seekable because
        // we got headers already
        if let Some(QueryState { seekable: false, .. }) = *self.query_state.lock().unwrap() {
            gst_debug!(self.cat, obj: src, "We're not seekable");
            return false;
        }

        // Otherwise we don't know yet if we're going to be seekable
        let start = segment.get_start();
        let stop = match segment.get_stop() {
            u64::MAX => None,
            stop => Some(stop),
        };

        gst_debug!(self.cat, obj: src, "Seeking to {:?}-{:?}", start, stop);
        let mut streaming_state = self.streaming_state.lock().unwrap();

        // In Ready we just remember the seek position, in Stopped we fail and in
        // Started we wait have to get the current request and then do more
        match *streaming_state {
            StreamingState::Ready { start: ref mut old_start, stop: ref mut old_stop, .. } => {
                *old_start = start;
                *old_stop = stop;
                return true;
            },
            StreamingState::Stopped => {
                gst_element_error!(src, gst::LibraryError::Failed, ["Not started yet"]);
                return false;
            }
            StreamingState::Started { .. } => (),
        };

        // TODO: headers can be in streaming state or not?
        //
        // TODO: Race condition: we might not have headers above, but when we lock() the request
        // it might already be blocking on getting a Chunk

        // If we're currently in create(), this will block until the headers were received
        // and parsed, otherwise if no headers are there after locking it's up to us to
        // wait for the headers or flushing/error here
        let request = self.request.lock().unwrap();

        let wait_seekable = match *self.query_state.lock().unwrap() {
            None => {
                true
            }
            Some(QueryState { seekable, .. }) if !seekable => {
                gst_debug!(self.cat, obj: src, "Not seekable");
                return false;
            },
            _ => false,
        };

        if wait_seekable {
            // TODO wait for the headers or flushing/error, parse headers

            // TODO: return here if not seekable
        }

        // TODO: Check against known size and warn

        {
            let mut closer = self.closer.lock().unwrap();
            closer.as_ref().map(|c| c.close());
            *closer = None;
        }

        *old_start = start;
        *old_stop = stop;
        self.do_request(src, command_sender, uri.clone(), start, stop);
        true
    }

    fn is_seekable(&self, _src: &BaseSrc) -> bool {
        // TODO If started and unknown, wait for headers

        match *self.query_state.lock().unwrap() {
            Some(QueryState { seekable, .. }) => seekable,
            _ => false,
        }
    }

    fn get_size(&self, _src: &BaseSrc) -> Option<u64> {
        // TODO If started and unknown, wait for headers

        match *self.query_state.lock().unwrap() {
            Some(QueryState { size, .. }) => size,
            _ => None,
        }
    }
}

impl URIHandlerImpl for HttpSrc {
    fn get_uri(&self, element: &gst::URIHandler) -> Option<String> {
        HttpSrc::get_uri(self, &element.clone().upcast())
    }

    fn set_uri(&self, element: &gst::URIHandler, uri: Option<String>) -> Result<(), glib::Error> {
        HttpSrc::set_uri(self, &element.clone().upcast(), uri)
    }
}

struct HttpSrcStatic;

impl ImplTypeStatic<BaseSrc> for HttpSrcStatic {
    fn get_name(&self) -> &str {
        "HttpSrc"
    }

    fn new(&self, element: &BaseSrc) -> Box<BaseSrcImpl<BaseSrc>> {
        HttpSrc::init(element)
    }

    fn class_init(&self, klass: &mut BaseSrcClass) {
        HttpSrc::class_init(klass);
    }

    fn type_init(&self, token: &TypeInitToken, type_: glib::Type) {
        register_uri_handler(token, type_, self);
    }
}

impl URIHandlerImplStatic<BaseSrc> for HttpSrcStatic {
    fn get_impl<'a>(&self, imp: &'a Box<BaseSrcImpl<BaseSrc>>) -> &'a URIHandlerImpl {
        imp.downcast_ref::<HttpSrc>().unwrap()
    }

    fn get_type(&self) -> gst::URIType {
        gst::URIType::Src
    }

    fn get_protocols(&self) -> Vec<String> {
        vec!["http".into(), "https".into()]
    }
}

pub fn register(plugin: &gst::Plugin) {
    let httpsrc_static = HttpSrcStatic;
    let type_ = register_type(httpsrc_static);
    gst::Element::register(plugin, "rshttpsrc", 256 + 10, type_);
}

mod io_thread {
    use url::Url;
    use futures;
    use futures::{Future, Sink, Stream};
    use futures::{future, stream};
    use futures::task::Task;
    use futures::sync::mpsc;
    use tokio_core::reactor::Core;
    use reqwest::unstable::async::{Chunk, Client};
    use reqwest::header::{Headers, AcceptRanges, ByteRangeSpec, ContentLength, ContentRange,
                          ContentRangeSpec, Range, RangeUnit};
    use std::sync::{Arc, Condvar, Mutex, Weak};
    use std::collections::VecDeque;

    // Trait for getting the size in bytes for Items that are transferred via the bounded
    // ItemChannel<T> below
    pub trait Item {
        fn get_size(&self) -> usize;
    }

    const CHANNEL_MAX_COUNT: usize = 100;
    const CHANNEL_MAX_BYTES: usize = 2_000_000;

    // Channel that provides a tokio Sink for sending items and a blocking, single Receiver for
    // receiving items. In addition a asynchronous "Closer" is provided that can unblock the
    // Receiver and shut down the whole channel at any time
    //
    // Only the Receiver and Closer are public API from this module, the Sink is only used
    // internally to be filled with items from the IO thread
    //
    // Once the Receiver disappears, the Sink yields Err(()). Once all Sinks disappeared, the
    // Receiver will yield None. The same happens if the channel is closed via the Closer.
    //
    // Up to CHANNEL_MAX_COUNT items / CHANNEL_MAX_BYTES bytes are buffered inside the channel
    struct ItemChannel<T: Item> {
        inner: Mutex<ItemChannelInner<T>>,
        cond: Condvar,
    }

    struct ItemChannelInner<T: Item> {
        items: VecDeque<T>,
        items_size: usize,
        tasks: Vec<Task>,
        receiver_alive: bool,
        sink_count: u32,
        closed: bool,
    }

    impl<T: Item> ItemChannel<T> {
        fn new() -> (ItemSink<T>, ItemReceiver<T>, ItemChannelCloser<T>) {
            let channel = Arc::new(ItemChannel {
                inner: Mutex::new(ItemChannelInner {
                    items: VecDeque::with_capacity(CHANNEL_MAX_COUNT),
                    items_size: 0,
                    tasks: Vec::new(),
                    receiver_alive: true,
                    sink_count: 1,
                    closed: false,
                }),
                cond: Condvar::new(),
            });

            (
                ItemSink {
                    channel: channel.clone(),
                },
                ItemReceiver {
                    channel: channel.clone(),
                },
                ItemChannelCloser { channel: channel },
            )
        }
    }

    pub struct ItemReceiver<T: Item> {
        channel: Arc<ItemChannel<T>>,
    }

    impl<T: Item> ItemReceiver<T> {
        pub fn recv(&mut self) -> Option<T> {
            let mut inner = self.channel.inner.lock().unwrap();

            while inner.items.is_empty() {
                if inner.sink_count == 0 || inner.closed {
                    return None;
                }

                inner = self.channel.cond.wait(inner).unwrap();
            }

            let item = inner.items.pop_front().unwrap();
            inner.items_size -= item.get_size();
            for task in inner.tasks.drain(..) {
                task.notify();
            }

            Some(item)
        }
    }

    impl<T: Item> Drop for ItemReceiver<T> {
        fn drop(&mut self) {
            let mut inner = self.channel.inner.lock().unwrap();
            inner.receiver_alive = false;

            for task in inner.tasks.drain(..) {
                task.notify();
            }
        }
    }

    #[derive(Clone)]
    pub struct ItemChannelCloser<T: Item> {
        channel: Arc<ItemChannel<T>>,
    }

    impl<T: Item> ItemChannelCloser<T> {
        pub fn close(&self) {
            let mut inner = self.channel.inner.lock().unwrap();
            inner.closed = true;

            inner.items.clear();
            inner.items_size = 0;
            self.channel.cond.notify_one();
            for task in inner.tasks.drain(..) {
                task.notify();
            }
        }
    }

    struct ItemSink<T: Item> {
        channel: Arc<ItemChannel<T>>,
    }

    impl<T: Item> Clone for ItemSink<T> {
        fn clone(&self) -> Self {
            let res = ItemSink {
                channel: self.channel.clone(),
            };

            let mut inner = self.channel.inner.lock().unwrap();
            inner.sink_count += 1;

            res
        }
    }

    impl<T: Item> Sink for ItemSink<T> {
        type SinkItem = T;
        type SinkError = ();

        fn start_send(&mut self, item: T) -> futures::StartSend<T, ()> {
            let mut inner = self.channel.inner.lock().unwrap();

            // We're supposed to be dead already, or the receiver is closed
            if !inner.receiver_alive || inner.closed {
                return Err(());
            }

            // We already have some data queued up, wait to get some space again
            if inner.items.len() >= CHANNEL_MAX_COUNT || inner.items_size >= CHANNEL_MAX_BYTES {
                if !inner.tasks.iter().any(|t| t.will_notify_current()) {
                    inner.tasks.push(futures::task::current());
                }
                return Ok(futures::AsyncSink::NotReady(item));
            }

            inner.items_size += item.get_size();
            inner.items.push_back(item);
            self.channel.cond.notify_one();

            Ok(futures::AsyncSink::Ready)
        }

        fn poll_complete(&mut self) -> futures::Poll<(), ()> {
            let mut inner = self.channel.inner.lock().unwrap();

            if inner.items.is_empty() {
                Ok(futures::Async::Ready(()))
            } else if !inner.receiver_alive || inner.closed {
                Err(())
            } else {
                if !inner.tasks.iter().any(|t| t.will_notify_current()) {
                    inner.tasks.push(futures::task::current());
                }
                Ok(futures::Async::NotReady)
            }
        }

        fn close(&mut self) -> futures::Poll<(), ()> {
            self.poll_complete()
        }
    }

    impl<T: Item> Drop for ItemSink<T> {
        fn drop(&mut self) {
            let mut inner = self.channel.inner.lock().unwrap();
            assert!(inner.sink_count > 0);
            inner.sink_count -= 1;
            self.channel.cond.notify_one();
        }
    }

    // Commands to send to the IO thread
    enum Command {
        // Start a new HTTP request for url with range start-stop
        // and provide items via the sink to the connected receiver
        Request {
            url: Url,
            start: u64,
            stop: Option<u64>,
            sink: ItemSink<RequestItem>,
        },
    }

    // Items returned by Command::Request via the Sink
    #[derive(Debug)]
    pub enum RequestItem {
        Headers(Headers),
        Error(String),
        Chunk(Chunk),
        Eos,
    }

    impl Item for RequestItem {
        fn get_size(&self) -> usize {
            if let RequestItem::Chunk(ref chunk) = *self {
                chunk.len()
            } else {
                0
            }
        }
    }

    // FIXME: While Sender is cloneable as-is, we nonetheless put it into an Arc<Mutex<_>> so
    // that we can create a weak-reference to it. This is inefficient but seems to be the simplest
    // way to keep the thread running as long as at least a single Sender is alive and keep a weak
    // reference to be able to create more Senders while it is running
    #[derive(Clone)]
    pub struct CommandSender(Arc<CommandSenderInner>);
    type CommandSenderInner = Mutex<mpsc::Sender<Command>>;

    // Weak reference to the Sender that is currently running the thread, if any. Will be cloned
    // for any new user of the thread and will become destroyed once no Sender is referenced
    // anymore
    lazy_static! {
        static ref COMMAND_SENDER: Mutex<Weak<CommandSenderInner>> = Mutex::new(Weak::new());
    }

    impl CommandSender {
        // Convenience wrapper around Command::Request that simply returns
        // the Receiver and Closer
        pub fn request(
            &self,
            url: Url,
            start: u64,
            stop: Option<u64>,
        ) -> (ItemReceiver<RequestItem>, ItemChannelCloser<RequestItem>) {
            let (sink, receiver, closer) = ItemChannel::new();

            let mut sender = self.0.lock().unwrap();
            sender
                .try_send(Command::Request {
                    url,
                    start,
                    stop,
                    sink,
                })
                .unwrap();

            (receiver, closer)
        }
    }

    // Gets a new reference to a CommandSender to send commands to the IO thread. If no thread is
    // currently running, a new one is spawned.
    pub fn get_command_sender() -> CommandSender {
        let mut command_sender = (*COMMAND_SENDER).lock().unwrap();

        match command_sender.upgrade() {
            None => {
                let sender = spawn_io_thread();
                *command_sender = Arc::downgrade(&sender.0);
                sender
            }
            Some(sender) => CommandSender(sender),
        }
    }

    fn spawn_io_thread() -> CommandSender {
        use std::thread;
        use std::sync::mpsc as std_mpsc;

        let (sender, receiver) = std_mpsc::sync_channel(0);

        thread::spawn(move || {
            let (f_sender, f_receiver) = mpsc::channel(5);
            sender.send(f_sender).unwrap();
            drop(sender);

            io_thread(f_receiver)
        });

        let sender = receiver.recv().unwrap();
        drop(receiver);

        CommandSender(Arc::new(Mutex::new(sender)))
    }

    // The actual IO thread function which handles Commands send via the CommandSender
    fn io_thread(f_receiver: mpsc::Receiver<Command>) {
        let mut core = Core::new().unwrap();
        let command_handle = core.handle();

        let client = Client::new(&command_handle);

        // They only possible error is the sender being closed
        let handle_commands = f_receiver.for_each(move |command| {
            match command {
                Command::Request {
                    url,
                    start,
                    stop,
                    sink,
                } => {
                    // TODO: handle_request() once we can use impl trait
                    let mut req = client.get(url);

                    match (start != 0, stop) {
                        (false, None) => (),
                        (true, None) => {
                            req.header(Range::Bytes(vec![ByteRangeSpec::AllFrom(start)]));
                        }
                        (_, Some(stop)) => {
                            req.header(Range::Bytes(vec![ByteRangeSpec::FromTo(start, stop - 1)]));
                        }
                    }

                    let req = req.send().then(move |res| {
                        let const_err_unit = |_| Err(());

                        // TODO: handle_response() once we can use impl trait
                        let res = match res {
                            Err(err) => {
                                let item = RequestItem::Error(format!("Request failed: {:?}", err));
                                return future::Either::A(
                                    sink.send_all(stream::once(Ok(item))).then(const_err_unit),
                                );
                            }
                            Ok(res) => res,
                        };

                        if !res.status().is_success() {
                            let item = RequestItem::Error(format!("Request failed: {:?}", res));
                            return future::Either::A(
                                sink.send_all(stream::once(Ok(item))).then(const_err_unit)
                            );
                        }

                        // TODO: start_download() once we can use impl trait
                        future::Either::B(
                            sink.send((RequestItem::Headers(res.headers().clone())))
                                .and_then(|sink| {
                                    let body = res.into_body();

                                    let sink_err = sink.clone();
                                    body.or_else(move |err| {
                                        let sink = sink_err.clone();
                                        let item = RequestItem::Error(format!("Download error: {}", err));
                                        sink.send_all(stream::once(Ok(item))).then(|_| Err(()))
                                    }).map(RequestItem::Chunk)
                                      .chain(stream::once(Ok(RequestItem::Eos)))
                                      .forward(sink)
                                      .map(|_| ())
                                }),
                        )
                    });

                    command_handle.spawn(req);
                }
            }

            Ok(())
        });

        core.run(handle_commands).unwrap();
    }
}

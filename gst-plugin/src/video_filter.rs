// Copyright (C) 2017 Sebastian Dröge <sebastian@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;
use std::mem;

use glib_ffi;
use gobject_ffi;
use gst_ffi;
use gst_base_ffi;

use glib;
use glib::translate::*;
use gst;
use gst::prelude::*;
use gst_base;

use object::*;
use element::*;
use anyimpl::*;

pub trait VideoFilterImpl<T: VideoFilterBase>
    : AnyImpl + ObjectImpl<T> + ElementImpl<T> + Send + Sync + 'static {
    fn start(&self, _element: &T) -> bool {
        true
    }

    fn stop(&self, _element: &T) -> bool {
        true
    }

    fn transform_caps(
        &self,
        element: &T,
        direction: gst::PadDirection,
        caps: gst::Caps,
        filter: Option<&gst::Caps>,
    ) -> gst::Caps {
        element.parent_transform_caps(direction, caps, filter)
    }

    fn fixate_caps(
        &self,
        element: &T,
        direction: gst::PadDirection,
        caps: &gst::Caps,
        othercaps: gst::Caps,
    ) -> gst::Caps {
        element.parent_fixate_caps(direction, caps, othercaps)
    }

    fn set_caps(&self, _element: &T, _incaps: &gst::Caps, _outcaps: &gst::Caps) -> bool {
        true
    }

    fn accept_caps(&self, element: &T, direction: gst::PadDirection, caps: &gst::Caps) -> bool {
        element.parent_accept_caps(direction, caps)
    }

    fn query(&self, element: &T, direction: gst::PadDirection, query: &mut gst::QueryRef) -> bool {
        element.parent_query(direction, query)
    }

    fn transform_size(
        &self,
        element: &T,
        direction: gst::PadDirection,
        caps: &gst::Caps,
        size: usize,
        othercaps: &gst::Caps,
    ) -> Option<usize> {
        element.parent_transform_size(direction, caps, size, othercaps)
    }

    fn get_unit_size(&self, _element: &T, _caps: &gst::Caps) -> Option<usize> {
        unimplemented!();
    }

    fn sink_event(&self, element: &T, event: gst::Event) -> bool {
        element.parent_sink_event(event)
    }

    fn src_event(&self, element: &T, event: gst::Event) -> bool {
        element.parent_src_event(event)
    }

    fn transform(
        &self,
        _element: &T,
        _inbuf: &gst::Buffer,
        _outbuf: &mut gst::BufferRef,
    ) -> gst::FlowReturn {
        unimplemented!();
    }

    fn transform_ip(&self, _element: &T, _buf: &mut gst::BufferRef) -> gst::FlowReturn {
        unimplemented!();
    }
}

any_impl!(VideoFilterBase, VideoFilterImpl);

pub unsafe trait VideoFilterBase
    : IsA<gst::Element> + IsA<gst_base::VideoFilter> + ObjectType {
    fn parent_transform_caps(
        &self,
        direction: gst::PadDirection,
        caps: gst::Caps,
        filter: Option<&gst::Caps>,
    ) -> gst::Caps {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            match (*parent_klass).transform_caps {
                Some(f) => from_glib_full(f(
                    self.to_glib_none().0,
                    direction.to_glib(),
                    caps.into_ptr(),
                    filter.to_glib_none().0,
                )),
                None => caps,
            }
        }
    }

    fn parent_fixate_caps(
        &self,
        direction: gst::PadDirection,
        caps: &gst::Caps,
        othercaps: gst::Caps,
    ) -> gst::Caps {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            match (*parent_klass).fixate_caps {
                Some(f) => from_glib_full(f(
                    self.to_glib_none().0,
                    direction.to_glib(),
                    caps.to_glib_none().0,
                    othercaps.into_ptr(),
                )),
                None => othercaps,
            }
        }
    }

    fn parent_accept_caps(&self, direction: gst::PadDirection, caps: &gst::Caps) -> bool {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            (*parent_klass)
                .accept_caps
                .map(|f| {
                    from_glib(f(
                        self.to_glib_none().0,
                        direction.to_glib(),
                        caps.to_glib_none().0,
                    ))
                })
                .unwrap_or(false)
        }
    }

    fn parent_query(&self, direction: gst::PadDirection, query: &mut gst::QueryRef) -> bool {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            (*parent_klass)
                .query
                .map(|f| {
                    from_glib(f(
                        self.to_glib_none().0,
                        direction.to_glib(),
                        query.as_mut_ptr(),
                    ))
                })
                .unwrap_or(false)
        }
    }

    fn parent_transform_size(
        &self,
        direction: gst::PadDirection,
        caps: &gst::Caps,
        size: usize,
        othercaps: &gst::Caps,
    ) -> Option<usize> {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            (*parent_klass)
                .transform_size
                .map(|f| {
                    let mut othersize = 0;
                    let res: bool = from_glib(f(
                        self.to_glib_none().0,
                        direction.to_glib(),
                        caps.to_glib_none().0,
                        size,
                        othercaps.to_glib_none().0,
                        &mut othersize,
                    ));
                    if res {
                        Some(othersize)
                    } else {
                        None
                    }
                })
                .unwrap_or(None)
        }
    }

    fn parent_sink_event(&self, event: gst::Event) -> bool {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            (*parent_klass)
                .sink_event
                .map(|f| from_glib(f(self.to_glib_none().0, event.into_ptr())))
                .unwrap_or(false)
        }
    }

    fn parent_src_event(&self, event: gst::Event) -> bool {
        unsafe {
            let klass = self.get_class();
            let parent_klass =
                (*klass).get_parent_class() as *const gst_base_ffi::GstVideoFilterClass;
            (*parent_klass)
                .src_event
                .map(|f| from_glib(f(self.to_glib_none().0, event.into_ptr())))
                .unwrap_or(false)
        }
    }
}

pub unsafe trait VideoFilterClassExt<T: VideoFilterBase>
where
    T::ImplType: VideoFilterImpl<T>,
{
    fn configure(
        &mut self,
        mode: BaseTransformMode,
        passthrough_on_same_caps: bool,
        transform_ip_on_passthrough: bool,
    ) {
        unsafe {
            let klass = &mut *(self as *const Self as *mut gst_video_ffi::GstVideoFilterClass);

            klass.passthrough_on_same_caps = passthrough_on_same_caps.to_glib();
            klass.transform_ip_on_passthrough = transform_ip_on_passthrough.to_glib();
        }
    }

    fn override_vfuncs(&mut self, _: &ClassInitToken) {
        unsafe {
            let klass = &mut *(self as *const Self as *mut gst_video_ffi::GstVideoFilterClass);
            klass.set_info = Some(video_filter_set_info::<T>);
            klass.transform = Some(video_filter_transform::<T>);
            klass.transform_ip = Some(video_filter_transform_ip::<T>);
        }
    }
}

glib_wrapper! {
    pub struct VideoFilter(Object<InstanceStruct<VideoFilter>>): [gst_video::VideoFilter => gst_video_ffi::GstVideoFilter,
                                                                  gst_base::BaseTransform => gst_base_ffi::GstBaseTransform,
                                                                  gst::Element => gst_ffi::GstElement,
                                                                  gst::Object => gst_ffi::GstObject];

    match fn {
        get_type => || get_type::<VideoFilter>(),
    }
}

unsafe impl<T: IsA<gst::Element> + IsA<gst_base::BaseTransform> + IsA<gst_video::VideoFilter> + ObjectType> VideoFilterBase
    for T {
}
pub type VideoFilterClass = ClassStruct<VideoFilter>;

// FIXME: Boilerplate
unsafe impl VideoFilterClassExt<VideoFilter> for VideoFilterClass {}
unsafe impl BaseTransformClassExt<VideoFilter> for VideoFilterClass {}
unsafe impl ElementClassExt<VideoFilter> for VideoFilterClass {}

#[macro_export]
macro_rules! box_video_filter_impl(
    ($name:ident) => {
        box_element_impl!($name);

        impl<T: VideoFilterBase> VideoFilterImpl<T> for Box<$name<T>> {
            fn set_info(&self, element: &T, ) -> bool {
                let imp: &$name<T> = self.as_ref();
                imp.src_event(element, event)
            }

            fn transform(&self, element: &T, inframe: &gst_video::VideoFrame, outframe: &mut gst_video::VideoFrame) -> gst::FlowReturn {
                let imp: &$name<T> = self.as_ref();
                imp.transform(element, inframe, outframe)
            }

            fn transform_ip(&self, element: &T, frame: &mut gst_video::VideoFrame) -> gst::FlowReturn {
                let imp: &$name<T> = self.as_ref();
                imp.transform_ip(element, frame)
            }
        }
    };
);
box_video_filter_impl!(VideoFilterImpl);

impl ObjectType for VideoFilter {
    const NAME: &'static str = "RsVideoFilter";
    type GlibType = gst_base_ffi::GstVideoFilter;
    type GlibClassType = gst_base_ffi::GstVideoFilterClass;
    type ImplType = Box<VideoFilterImpl<Self>>;

    fn glib_type() -> glib::Type {
        unsafe { from_glib(gst_base_ffi::gst_video_filter_get_type()) }
    }

    fn class_init(token: &ClassInitToken, klass: &mut VideoFilterClass) {
        ElementClassExt::override_vfuncs(klass, token);
        BaseTransformClassExt::override_vfuncs(klass, token);
        VideoFilterClassExt::override_vfuncs(klass, token);
    }

    object_type_fns!();
}

unsafe extern "C" fn video_filter_set_info<T: VideoFilterBase>(
    ptr: *mut gst_base_ffi::GstVideoFilter,
    incaps: *mut gst_ffi::GstCaps,
    in_info: *mut gst_video_ffi::GstVideoInfo,
    outcaps: *mut gst_ffi::GstCaps,
    out_info: *mut gst_video_ffi::GstVideoInfo,
) -> glib_ffi::gboolean
where
    T::ImplType: VideoFilterImpl<T>,
{
    callback_guard!();
    floating_reference_guard!(ptr);
    let element = &*(ptr as *mut InstanceStruct<T>);
    let wrap: T = from_glib_borrow(ptr as *mut InstanceStruct<T>);
    let imp = &*element.imp;

    panic_to_error!(&wrap, &element.panicked, false, {
        imp.src_event(&wrap, from_glib_full(event))
    }).to_glib()
}

unsafe extern "C" fn video_filter_transform<T: VideoFilterBase>(
    ptr: *mut gst_base_ffi::GstVideoFilter,
    in_frame: *mut gst_video_ffi::GstVideoFrame,
    out_frame: *mut gst_video_ffi::GstVideoFrame,
) -> gst_ffi::GstFlowReturn
where
    T::ImplType: VideoFilterImpl<T>,
{
    callback_guard!();
    floating_reference_guard!(ptr);
    let element = &*(ptr as *mut InstanceStruct<T>);
    let wrap: T = from_glib_borrow(ptr as *mut InstanceStruct<T>);
    let imp = &*element.imp;

    panic_to_error!(&wrap, &element.panicked, gst::FlowReturn::Error, {
        imp.transform(
            &wrap,
            &from_glib_borrow(inbuf),
            gst::BufferRef::from_mut_ptr(outbuf),
        )
    }).to_glib()
}

unsafe extern "C" fn video_filter_transform_ip<T: VideoFilterBase>(
    ptr: *mut gst_base_ffi::GstVideoFilter,
    frame: *mut gst_video_ffi::GstVideoFrame,
) -> gst_ffi::GstFlowReturn
where
    T::ImplType: VideoFilterImpl<T>,
{
    callback_guard!();
    floating_reference_guard!(ptr);
    let element = &*(ptr as *mut InstanceStruct<T>);
    let wrap: T = from_glib_borrow(ptr as *mut InstanceStruct<T>);
    let imp = &*element.imp;

    // FIXME: Wrong signature in FFI
    let buf = buf as *mut gst_ffi::GstBuffer;

    panic_to_error!(&wrap, &element.panicked, gst::FlowReturn::Error, {
        imp.transform_ip(&wrap, gst::BufferRef::from_mut_ptr(buf))
    }).to_glib()
}

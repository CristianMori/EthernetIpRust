//! Standard CIP services shared across most classes:
//! `Get_Attribute_Single` (0x0E), `Set_Attribute_Single` (0x10), and
//! `Get_Attributes_All` (0x01). Handler bodies are pure functions on
//! [`CipInstance`] and are registered by [`CipClass::new`] /
//! [`CipClass::add_standard_instance_services`].

use crate::cip::attribute::AttributeAccess;
use crate::cip::instance::CipInstance;
use crate::cip::service::{CipServiceRequest, CipServiceResponse};
use crate::cip::status;

pub const GET_ATTRIBUTES_ALL: u8 = 0x01;
pub const GET_ATTRIBUTE_SINGLE: u8 = 0x0E;
pub const SET_ATTRIBUTE_SINGLE: u8 = 0x10;

/// Handle `Get_Attribute_Single`: attribute id comes from the request path,
/// response body is the raw attribute bytes.
pub fn handle_get_attribute_single(
    instance: &mut CipInstance,
    request: &CipServiceRequest,
) -> CipServiceResponse {
    let Some(attr_id) = request.path.attribute_id else {
        return CipServiceResponse::error(request.service_code, status::PATH_SEGMENT_ERROR);
    };
    let attr_id = attr_id as u16;
    let Some(attr) = instance.get_attribute(attr_id) else {
        return CipServiceResponse::error(request.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    };
    if !attr.access.contains(AttributeAccess::GET_SINGLE) {
        return CipServiceResponse::error(request.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    }
    CipServiceResponse::success_with(request.service_code, attr.data().into_owned())
}

/// Handle `Set_Attribute_Single`: attribute id from the path, new bytes from
/// the request body. Enforces the `SET_SINGLE` access flag and refuses a
/// length mismatch (attribute stores are fixed-width per CIP).
pub fn handle_set_attribute_single(
    instance: &mut CipInstance,
    request: &CipServiceRequest,
) -> CipServiceResponse {
    let Some(attr_id) = request.path.attribute_id else {
        return CipServiceResponse::error(request.service_code, status::PATH_SEGMENT_ERROR);
    };
    let attr_id = attr_id as u16;
    let Some(attr) = instance.get_attribute_mut(attr_id) else {
        return CipServiceResponse::error(request.service_code, status::ATTRIBUTE_NOT_SUPPORTED);
    };
    if !attr.access.contains(AttributeAccess::SET_SINGLE) {
        return CipServiceResponse::error(request.service_code, status::ATTRIBUTE_NOT_SETTABLE);
    }
    if request.data.len() != attr.len() {
        return CipServiceResponse::error(request.service_code, status::INVALID_ATTRIBUTE_VALUE);
    }
    attr.set_data(&request.data);
    CipServiceResponse::success(request.service_code)
}

/// Handle `Get_Attributes_All`: response body is the concatenation of every
/// attribute marked `GET_ALL`, in ascending id order (matches C# / C++).
pub fn handle_get_attributes_all(
    instance: &mut CipInstance,
    request: &CipServiceRequest,
) -> CipServiceResponse {
    let mut body = Vec::new();
    for attr in instance.attributes() {
        if attr.access.contains(AttributeAccess::GET_ALL) {
            body.extend_from_slice(attr.data().as_ref());
        }
    }
    CipServiceResponse::success_with(request.service_code, body)
}

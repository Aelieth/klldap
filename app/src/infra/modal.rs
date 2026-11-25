#![allow(clippy::empty_docs)]

use std::{cell::Cell, rc::Rc};
use wasm_bindgen::prelude::*;
use yew::NodeRef;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = bootstrap)]
    pub type Modal;

    #[wasm_bindgen(constructor, js_namespace = bootstrap)]
    pub fn new(e: web_sys::Element) -> Modal;

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn show(this: &Modal);

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn hide(this: &Modal);
}

/// Owns a Bootstrap modal and the `NodeRef` it binds to. Components hold one of
/// these instead of a `(NodeRef, Option<Modal>)` pair: attach `node_ref()` to the
/// modal element, call `init_on_first_render` from `rendered`, then `show`/`hide`.
#[derive(Default)]
pub struct ModalHandle {
    node_ref: NodeRef,
    modal: Option<Bound>,
}

const OPENED: &str = "shown.bs.modal";

struct Dialog {
    modal: Modal,
    close_asked: Cell<bool>,
}

/// Bootstrap's `hide()` does nothing while the opening transition runs, so a close asked then
/// is carried out when `shown.bs.modal` says the opening has ended.
struct Bound {
    dialog: Rc<Dialog>,
    node: web_sys::Element,
    on_opened: Closure<dyn FnMut()>,
}

impl Bound {
    fn new(node: web_sys::Element) -> Self {
        let dialog = Rc::new(Dialog {
            modal: Modal::new(node.clone()),
            close_asked: Cell::new(false),
        });
        let opened = dialog.clone();
        let on_opened = Closure::<dyn FnMut()>::new(move || {
            if opened.close_asked.take() {
                opened.modal.hide();
            }
        });
        let listener = on_opened.as_ref().unchecked_ref();
        let _ = node.add_event_listener_with_callback(OPENED, listener);
        Self {
            dialog,
            node,
            on_opened,
        }
    }
}

impl Drop for Bound {
    fn drop(&mut self) {
        let listener = self.on_opened.as_ref().unchecked_ref();
        let _ = self
            .node
            .remove_event_listener_with_callback(OPENED, listener);
    }
}

impl ModalHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_ref(&self) -> NodeRef {
        self.node_ref.clone()
    }

    pub fn init_on_first_render(&mut self, first_render: bool) {
        if first_render {
            self.modal = Some(Bound::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    /// For a page whose modal is not rendered until its data has loaded.
    pub fn init_once(&mut self) {
        if self.modal.is_none()
            && let Some(node) = self.node_ref.cast::<web_sys::Element>()
        {
            self.modal = Some(Bound::new(node));
        }
    }

    pub fn show(&self) {
        if let Some(bound) = &self.modal {
            bound.dialog.close_asked.set(false);
            bound.dialog.modal.show();
        }
    }

    pub fn hide(&self) {
        if let Some(bound) = &self.modal {
            bound.dialog.close_asked.set(true);
            bound.dialog.modal.hide();
        }
    }
}

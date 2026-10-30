//! The OSyx UI toolkit.
//!
//! Widgets draw into any [`Surface`] (in practice a PRISM shared-memory
//! buffer) through a [`Painter`] that carries the clip rectangle, the
//! [`Theme`] and the [`Fonts`]. They are plain structs owned by the
//! application: it positions them (see [`layout`]), forwards [`Event`]s to
//! them and reacts to the [`Response`] they return. Keyboard focus moves
//! between widgets with a [`FocusChain`].
//!
//! Nothing here talks to the kernel or the compositor, so layout, hit
//! testing, focus and widget state are unit tested on the host.

#![no_std]

extern crate alloc;

pub mod clipboard;
pub mod event;
pub mod focus;
pub mod icon;
pub mod layout;
pub mod paint;
pub mod theme;
pub mod time;
pub mod widget;

#[cfg(test)]
mod tests;

pub use clipboard::Clipboard;
pub use event::{ClickCounter, Event, KeyEvent, Response};
pub use focus::FocusChain;
pub use icon::Icon;
pub use osyx_gfx::{rgb, Color, Rect, Surface};
pub use paint::{Align, FontKind, Fonts, Painter};
pub use theme::Theme;

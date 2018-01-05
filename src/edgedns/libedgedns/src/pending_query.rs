//! A `PendingQuery` is a query sent to upstream servers, whose response may
//! eventually be dispatched across multiple `ClientQuery` instances waiting for
//! the same response.

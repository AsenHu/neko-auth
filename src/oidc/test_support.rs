use core::{future, task};
use std::{cell, collections, pin, thread};
use time;

pub fn block_on<F>(future: F) -> F::Output
where
    F: future::Future,
{
    let waker = task::Waker::noop();
    let mut context = task::Context::from_waker(waker);
    let mut future = pin::pin!(future);

    loop {
        match future.as_mut().poll(&mut context) {
            task::Poll::Ready(output) => return output,
            task::Poll::Pending => thread::yield_now(),
        }
    }
}

pub struct Counter {
    calls: cell::Cell<usize>,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            calls: cell::Cell::new(0),
        }
    }

    pub fn increment(&self) {
        self.calls.set(self.calls.get() + 1);
    }

    pub fn get(&self) -> usize {
        self.calls.get()
    }
}

pub struct Script<T> {
    values: cell::RefCell<collections::VecDeque<T>>,
}

impl<T> Script<T> {
    pub fn new<const N: usize>(values: [T; N]) -> Self {
        Self {
            values: cell::RefCell::new(values.into_iter().collect()),
        }
    }

    pub fn next(&self, missing_value_message: &str) -> T {
        self.values
            .borrow_mut()
            .pop_front()
            .expect(missing_value_message)
    }
}

pub struct Recordings<T> {
    values: cell::RefCell<Vec<T>>,
}

impl<T> Recordings<T> {
    pub fn new() -> Self {
        Self {
            values: cell::RefCell::new(Vec::new()),
        }
    }

    pub fn push(&self, value: T) {
        self.values.borrow_mut().push(value);
    }

    pub fn borrow<'a>(&'a self) -> cell::Ref<'a, Vec<T>> {
        self.values.borrow()
    }

    pub fn is_empty(&self) -> bool {
        self.values.borrow().is_empty()
    }
}

pub struct StubClock {
    times: Script<time::OffsetDateTime>,
    calls: Counter,
}

impl StubClock {
    pub fn new<const N: usize>(times: [time::OffsetDateTime; N]) -> Self {
        Self {
            times: Script::new(times),
            calls: Counter::new(),
        }
    }

    pub fn now(&self) -> time::OffsetDateTime {
        self.calls.increment();
        self.times
            .next("missing configured current_time return value")
    }

    pub fn calls(&self) -> usize {
        self.calls.get()
    }
}

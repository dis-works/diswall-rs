use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use time::OffsetDateTime;

/// A timer that runs one function every hour at 0 minutes and 0 seconds
pub struct HourlyTimer {
    task: Option<Box<dyn Fn() + Send + Sync + 'static>>,
    stop: Arc<AtomicBool>
}

impl HourlyTimer {
    pub fn new<F: Fn() + Send + Sync + 'static>(task: F)  -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        Self { task: Some(Box::new(task)), stop }
    }

    pub fn start(&mut self) -> TimerHandle {
        let handle= TimerHandle::new(self.stop.clone());
        self.start_loop();
        handle
    }

    fn start_loop(&mut self) {
        let stop = self.stop.clone();
        let second = Duration::from_secs(1);
        if let Some(task) = self.task.take() {
            thread::spawn(move || {
                loop {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let now = OffsetDateTime::now_utc();
                    if now.minute() == 0 && now.second() == 0 {
                        task()
                    }
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    thread::sleep(second);
                }
            });
        }
    }
}

#[allow(dead_code)]
pub struct TimerHandle {
    stop: Arc<AtomicBool>
}

impl TimerHandle {
    fn new(stop: Arc<AtomicBool>) -> Self {
        Self { stop }
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    #[allow(dead_code)]
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}
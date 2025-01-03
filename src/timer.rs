use std::future::Future;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Notify;
use tokio::time::{interval_at, Duration, Instant};

/// A timer that runs one function every hour at 0 minutes and 0 seconds
pub struct HourlyTimer<Fut, F>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    task: Arc<F>,
    stop: Arc<Notify>,
}

impl<Fut, F> HourlyTimer<Fut, F>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    pub fn new(task: F) -> Self {
        Self {
            task: Arc::new(task),
            stop: Arc::new(Notify::new()),
        }
    }

    pub fn start(self) -> TimerHandle {
        let stop = self.stop.clone();
        let task = self.task.clone();
        tokio::spawn(async move {
            let mut interval = Self::get_hourly_interval().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        task().await; // Run the async task
                    }
                    _ = stop.notified() => {
                        break;
                    }
                }
            }
        });

        TimerHandle { stop: self.stop.clone() }
    }

    async fn get_hourly_interval() -> tokio::time::Interval {
        let now = OffsetDateTime::now_utc();
        let next_hour = now
            .replace_minute(0).unwrap()
            .replace_second(0).unwrap()
            + Duration::from_secs(3600);

        let start_time = Instant::now() + (next_hour - now).try_into().unwrap();
        interval_at(start_time, Duration::from_secs(3600))
    }
}

/// A handle to stop the timer
#[allow(dead_code)]
pub struct TimerHandle {
    stop: Arc<Notify>,
}

impl TimerHandle {
    #[allow(dead_code)]
    pub fn stop(self) {
        self.stop.notify_one();
    }
}
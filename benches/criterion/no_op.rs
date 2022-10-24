use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use futures::stream::{self, StreamExt};
use pprof::criterion::{Output, PProfProfiler};

struct AsyncRuntime(tokio_uring::Runtime);

impl criterion::async_executor::AsyncExecutor for &AsyncRuntime {
    fn block_on<T>(&self, future: impl futures::Future<Output = T>) -> T {
        self.0.block_on(future)
    }
}

#[derive(Clone)]
struct Options {
    iterations: usize,
    concurrency: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            iterations: 100000,
            concurrency: 1,
        }
    }
}

async fn run_no_ops(opts: &Options) {
    stream::iter(0..opts.iterations)
        .for_each_concurrent(Some(opts.concurrency), |_| async move {
            tokio_uring::no_op().await.unwrap();
        })
        .await
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("no_op");
    let mut opts = Options::default();

    let mut ring_opts = tokio_uring::uring_builder();
    ring_opts
        .setup_cqsize(256)
        // .setup_sqpoll(10)
        // .setup_sqpoll_cpu(1)
        ;

    let mut builder = tokio_uring::builder();
    builder.entries(128).uring_builder(&ring_opts);

    let runtime = AsyncRuntime(tokio_uring::Runtime::new(&builder).unwrap());
    let runtime = &runtime;

    for concurrency in [1, 32, 64, 256].iter() {
        opts.concurrency = *concurrency;

        // We perform long running benchmarks: this is the best mode
        group.throughput(Throughput::Elements(opts.iterations as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &opts,
            |b, opts| {
                // Custom iterator used because we don't expose access to runtime,
                // which is required to do async benchmarking with criterion
                b.to_async(runtime).iter(|| run_no_ops(opts));
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    targets = bench
}
criterion_main!(benches);

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use hyper::client::connect::dns::Name;
use pin_project_lite::pin_project;
use reqwest::dns::{Addrs, Resolve, Resolving};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::TokioAsyncResolver;

struct CustomResolver {
    inner: TokioAsyncResolver,
}

impl Resolve for CustomResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let inner = self.inner.clone();
        let fut = inner.lookup_ip(name.as_str().to_owned());

        Box::pin(CustomResolverFuture { inner: fut })
    }
}

pin_project! {
    struct CustomResolverFuture<T> {
        #[pin]
        inner: T,
    }
}

impl<T> Future for CustomResolverFuture<T>
where
    T: Future<Output = Result<LookupIp, ResolveError>>,
{
    type Output = Result<Addrs, Box<dyn std::error::Error + Send + Sync>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let addrs = ready!(this.inner.poll(cx)).unwrap();

        let filtered = addrs
            .into_iter()
            .filter(|addr| match addr {
                IpAddr::V4(inner) => !inner.is_private(),
                IpAddr::V6(_) => true,
            })
            .map(|addr| SocketAddr::new(addr, 443));

        Poll::Ready(Ok(Box::new(filtered)))
    }
}

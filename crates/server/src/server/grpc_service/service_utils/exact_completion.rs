//! Exact adapters capture origin before output validation, policy, or settlement
//! can replace the caller-visible RV. No native payload participates in health.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompletionOrigin {
    Rejected { rv: CkRv },
    Provider { rv: CkRv },
}

pub(in crate::server::grpc_service) struct ExactCompletion<T> {
    origin: CompletionOrigin,
    result: CkResult<T>,
}

/// The exact backend contract reserves Err for pre-native rejection. Every
/// completed provider RV is embedded in the first result channel, even on error.
pub(in crate::server::grpc_service) trait ProviderCompletion {
    fn provider_rv(&self) -> CkRv;
}
impl ProviderCompletion for CkRv {
    fn provider_rv(&self) -> CkRv {
        *self
    }
}
impl ProviderCompletion for CkOutputBufferResult {
    fn provider_rv(&self) -> CkRv {
        self.ck_rv
    }
}
impl ProviderCompletion for CkOutputAndHandleResult {
    fn provider_rv(&self) -> CkRv {
        self.ck_rv
    }
}
impl ProviderCompletion for CkParameterRoundtripResult {
    fn provider_rv(&self) -> CkRv {
        self.ck_rv
    }
}
impl<A: ProviderCompletion, B> ProviderCompletion for (A, B) {
    fn provider_rv(&self) -> CkRv {
        self.0.provider_rv()
    }
}
impl<A: ProviderCompletion, B, C> ProviderCompletion for (A, B, C) {
    fn provider_rv(&self) -> CkRv {
        self.0.provider_rv()
    }
}

impl<T: ProviderCompletion> ExactCompletion<T> {
    pub(in crate::server::grpc_service) fn capture(result: CkResult<T>) -> Self {
        let origin = match &result {
            Ok(value) => CompletionOrigin::Provider { rv: value.provider_rv() },
            Err(rv) => CompletionOrigin::Rejected { rv: *rv },
        };
        Self { origin, result }
    }
}
impl<T> ExactCompletion<T> {
    /// Preserve original completion evidence through all fallible service-side
    /// transformations, including fail-closed invalid-output suppression.
    pub(in crate::server::grpc_service) fn map_result<U>(
        self,
        transform: impl FnOnce(CkResult<T>) -> CkResult<U>,
    ) -> ExactCompletion<U> {
        ExactCompletion { origin: self.origin, result: transform(self.result) }
    }

    fn health(&self) -> Option<bool> {
        match self.origin {
            CompletionOrigin::Rejected { .. } => None,
            CompletionOrigin::Provider { rv } => Some(provider_rv_is_healthy(rv)),
        }
    }
}

/// Same timeout/breaker/context-guard machinery as ordinary calls, but classify
/// the provider completion, not the transformed result or preparatory errors.
pub(in crate::server::grpc_service) async fn spawn_backend_exact<T, F>(
    operation: F,
) -> Result<CkResult<T>, Status>
where
    T: Send + 'static,
    F: FnOnce() -> ExactCompletion<T> + Send + 'static,
{
    let result = spawn_backend_core_classified(
        &IN_FLIGHT,
        &STUCK_CALLS,
        backend_timeout(),
        max_concurrent_backend_calls(),
        move || Ok(operation()),
        |result| match result {
            Ok(Ok(completion)) => completion.health(),
            Err(_) => Some(false),
            // The timeout and breaker branches report failure before returning.
            Ok(Err(_)) => None,
        },
    )
    .await?;
    match result {
        Ok(completion) => Ok(completion.result),
        Err(error) => Ok(Err(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_completion_origin_survives_invalid_effect_suppression() {
        for provider_rv in
            [CkRv::OK, CkRv::DEVICE_REMOVED, CkRv::HOST_MEMORY, CkRv::FUNCTION_FAILED]
        {
            let completion =
                ExactCompletion::capture(Ok(CkOutputBufferResult::no_effects(provider_rv)))
                    .map_result(|_| Err::<(), _>(CkRv::DEVICE_ERROR));
            assert_eq!(completion.origin, CompletionOrigin::Provider { rv: provider_rv });
            assert_eq!(completion.result, Err(CkRv::DEVICE_ERROR));
            assert_eq!(completion.health(), Some(provider_rv_is_healthy(provider_rv)));
        }
    }

    #[test]
    fn exact_request_rejection_neither_degrades_nor_recovers_health() {
        for rv in [CkRv::HOST_MEMORY, CkRv::ARGUMENTS_BAD, CkRv::MECHANISM_PARAM_INVALID] {
            let completion = ExactCompletion::<CkOutputBufferResult>::capture(Err(rv));
            assert_eq!(completion.origin, CompletionOrigin::Rejected { rv });
            assert_eq!(completion.health(), None);
        }
    }
}

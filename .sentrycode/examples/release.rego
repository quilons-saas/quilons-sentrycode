package sentrycode.release

# Optional OPA/Rego policy. SentryCode combines this decision with its built-in
# policy result and always keeps the stricter outcome.
decision := "FAIL" if {
  input.repository.isDirty
}

decision := input.builtinDecision if {
  not input.repository.isDirty
}

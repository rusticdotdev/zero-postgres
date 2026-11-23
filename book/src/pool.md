# Pool

## Dynamic Credentials

In production, the credentials are short-lived and rotated.
For example, an AWS RDS IAM token is rotated every 15 minutes.

Use `Opts.password_fn` or `Opts.oauth_bearer_token_fn` so that new connections get fresh credentials.

```rust
opts.password_fn = Some(Arc::new(|| Ok(current_token())));
let pool = Pool::new(opts);
```

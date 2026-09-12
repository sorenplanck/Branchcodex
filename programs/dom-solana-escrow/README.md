> Candidato 0.2.0: state e rent são retidos após claim/refund; Close é
> recusado. Use `sweep_terminal_excess_v2` para excedentes. A implantação não
> foi alterada. Compatibilidade e limites: `../../docs/interop/hardening/ENTREGA-20260908.md`.

# DOM Solana Escrow Program

Program ID:

```text
3KN5WMzZsmwDCfKYheaVgx8Xo4veke815LJo3iYrdeNw
```

The program is intentionally a standalone Cargo workspace because the DOM host
workspace remains on Rust 1.75 while current Solana tooling may require a newer
toolchain.

Supported in V1:

- native SOL;
- classic SPL Token Program (`Tokenkeg...`);
- same-252-bit secret checked through the Solana Curve25519 syscall;
- permissionless claim/refund execution to frozen destinations;
- timestamp refund;
- post-terminal account close.

Token-2022 is rejected. Upgrade authority must be revoked before a production
profile can set `require_immutable_program=true`.

Build:

```bash
cargo build-sbf --manifest-path programs/dom-solana-escrow/Cargo.toml
```

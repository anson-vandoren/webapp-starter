# Setup

```sh
mise generate git-pre-commit --write --task=pre-commit
```

- Update the project name in `Cargo.toml`
- Copy `.env.sample` to `.env` and set database name
- In `src/config.rs`, update `ROOT_KEY_NAME`
- Update `templates/layout/base.html` with title & description
- Start adding content in `templates/auth/home.html`

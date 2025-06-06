# Changelog

## [0.9.1](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.9.0...v0.9.1) (2025-06-06)


### Bug Fixes

* **systemd:** Add User to systemd service ([b022133](https://github.com/compute-blade-community/compute-blade-agent/commit/b02213386036ac29a0f1a733395c44a87b3c00e2))

## [0.9.0](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.8.2...v0.9.0) (2025-06-06)

Re-Release of [v0.7.0](#070-2025-05-11), [v0.8.0](#080-2025-05-24), [v0.8.1](#081-2025-05-24), and , [v0.8.2](#082-2025-05-24) in the [compute-blade-community](https://github.com/compute-blade-community) GitHub Org

### ⚠ BREAKING CHANGES

* **docker:** Docker Images are now available & published

### Documentation

* **release:** document release process ([f6a70fa](https://github.com/compute-blade-community/compute-blade-agent/commit/f6a70fa6a389d31a82dac9e340c1704053b198c0))

## [0.8.2](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.8.1...v0.8.2) (2025-05-24)

### Bug Fixes

* auth to ghcr.io ([#63](https://github.com/compute-blade-community/compute-blade-agent/issues/63)) ([e600d32](https://github.com/compute-blade-community/compute-blade-agent/commit/e600d3245317eafe7df0090e7bc6f1dff45a5693))

## [0.8.1](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.8.0...v0.8.1) (2025-05-24)

### Bug Fixes

* set goreleaser version to v2.x ([#61](https://github.com/compute-blade-community/compute-blade-agent/issues/61)) ([08a4e9b](https://github.com/compute-blade-community/compute-blade-agent/commit/08a4e9bca67f53e69fec3ce4cdf93344f2cf1327))

## [0.8.0](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.7.0...v0.8.0) (2025-05-24)

### ⚠ BREAKING CHANGES

* **go version:** Bump go version to 1.24 ([#58](https://github.com/compute-blade-community/compute-blade-agent/issues/58))

### Miscellaneous Chores

* **go version:** Bump go version to 1.24 ([#58](https://github.com/compute-blade-community/compute-blade-agent/issues/58)) ([bb7b8cd](https://github.com/compute-blade-community/compute-blade-agent/commit/bb7b8cd55d88954bb2632606e12b2c9eb057690a))

## [0.7.0](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.6...v0.7.0) (2025-05-11)

### ⚠ BREAKING CHANGES

* **agent:** add support for mTLS authentication in gRPC server ([#54](https://github.com/compute-blade-community/compute-blade-agent/issues/54))

### Features

* **agent:** add support for mTLS authentication in gRPC server ([#54](https://github.com/compute-blade-community/compute-blade-agent/issues/54)) ([70541d8](https://github.com/compute-blade-community/compute-blade-agent/commit/70541d86bad675a153daf8b5c80a92de204502ab))
* **agent:** expose version, commit, and date information in logs for better tracking ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* **bladectl:** implement command structure for managing compute-blade features ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* **goreleaser:** add versioning information to builds for better traceability ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))

### Bug Fixes

* **.gitignore:** add .idea directory to ignore list to prevent IDE files from being tracked ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* **bladectl:** improve error handling in identify command for better user feedback ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))

## [0.6.6](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.5...v0.6.6) (2025-01-14)

### Bug Fixes

* correct package name from computeblade-agent to compute-blade-agent ([#47](https://github.com/compute-blade-community/compute-blade-agent/issues/47)) ([67b3411](https://github.com/compute-blade-community/compute-blade-agent/commit/67b3411e32df10673c5f3bab8b76f31f366cf3ab))

## [0.6.5](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.4...v0.6.5) (2024-08-31)

### Bug Fixes

* pin golang/tinygo versions ([ca690d4](https://github.com/compute-blade-community/compute-blade-agent/commit/ca690d418f099881b6aafdb2ca4be3cee6ac73fc))

## [0.6.4](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.3...v0.6.4) (2024-08-31)

### Bug Fixes

* finalize renaming ([158e7fc](https://github.com/compute-blade-community/compute-blade-agent/commit/158e7fc1bde46e66327d70f87743df39070c2753))

## [0.6.3](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.2...v0.6.3) (2024-08-05)

### Bug Fixes

* oci reg typo ([3cbf7a8](https://github.com/compute-blade-community/compute-blade-agent/commit/3cbf7a8733dedde834f7392de0851c971a6e3a05))

## [0.6.2](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.1...v0.6.2) (2024-08-05)

### Bug Fixes

* cleanup uf2 files ([d088a1b](https://github.com/compute-blade-community/compute-blade-agent/commit/d088a1ba0a1adba7694a7d2d3b7d49bb9c72fe0c))

## [0.6.1](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.6.0...v0.6.1) (2024-08-05)

### Bug Fixes

* bump tinygo release ([#39](https://github.com/compute-blade-community/compute-blade-agent/issues/39)) ([3278678](https://github.com/compute-blade-community/compute-blade-agent/commit/32786787683e2a0cd42b63b92fe7dd2c41bb6e8f))

## [0.6.0](https://github.com/compute-blade-community/compute-blade-agent/compare/v0.5.0...v0.6.0) (2024-08-05)

### Features

* migrate to compute-blade-community gh org ([#37](https://github.com/compute-blade-community/compute-blade-agent/issues/37)) ([6421521](https://github.com/compute-blade-community/compute-blade-agent/commit/6421521bfc94a6211ed084bf8913f413e27e5b14))

## [0.5.0](https://github.com/github.com/compute-blade-community/compute-blade-agent/compare/v0.4.1...v0.5.0) (2023-11-25)

### Features

* add smart fan unit support ([#29](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/29)) ([9992037](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/99920370fba8176dc34243d28281aa343f437fc5))

### Bug Fixes

* smart fan unit improvements ([#31](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/31)) ([a8d470d](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/a8d470d4f9ec2749e1067474805f67639cd24c09))

## [0.4.1](https://github.com/github.com/compute-blade-community/compute-blade-agent/compare/v0.4.0...v0.4.1) (2023-10-05)

### Bug Fixes

* ${ -&gt; ${{ ... ([#27](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/27)) ([f2cd029](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/f2cd029d83329085354acb7ed68da390dfe9aee4))
* add debug statement ([#25](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/25)) ([21d9942](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/21d99426293b724f53f0de594fce21e5c49724f8))
* debug statement ([#26](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/26)) ([780455e](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/780455e749a6acd896ce862ac565f1d1f5467c20))
* if statement? ([#23](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/23)) ([4691e2b](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/4691e2b3d71b9c28ebbed31b564c5356713b91f9))
* rename release-please -&gt; release workflow ([#28](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/28)) ([e86b221](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/e86b221aa886f11d6303521787ca4c755b114a6e))

## [0.4.0](https://github.com/github.com/compute-blade-community/compute-blade-agent/compare/v0.3.4...v0.4.0) (2023-10-05)

### Features

* switch to release-please ([#19](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/19)) ([33dd6e5](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/33dd6e5adf45d2b59c1af061c7e78c9426329f15))

### Bug Fixes

* explicitly check for true before running goreleaser ([#21](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/21)) ([9c82b60](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/9c82b60fd88718ad90a9a0aa774ffc4bcdd18d3f))
* if condition ([#22](https://github.com/github.com/compute-blade-community/compute-blade-agent/issues/22)) ([cee6912](https://github.com/github.com/compute-blade-community/compute-blade-agent/commit/cee6912f5768a310c2758c8755b9ed1985b10d23))

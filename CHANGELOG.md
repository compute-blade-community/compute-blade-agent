# Changelog

## [0.7.0](https://github.com/compute-blade-community/compute-blade-agent/compare/compute-blade-agent-v0.6.6...compute-blade-agent-v0.7.0) (2025-06-06)


### ⚠ BREAKING CHANGES

* **go version:** Bump go version to 1.24 ([#58](https://github.com/compute-blade-community/compute-blade-agent/issues/58))
* **agent:** add support for mTLS authentication in gRPC server ([#54](https://github.com/compute-blade-community/compute-blade-agent/issues/54))
* more refactoring

### Features

* add automated release pipeline + initial CI ([47ef404](https://github.com/compute-blade-community/compute-blade-agent/commit/47ef404dd7e28169131dfffebaa9d02f2751b3b3))
* add configuration support, update docs ([#18](https://github.com/compute-blade-community/compute-blade-agent/issues/18)) ([7f166f2](https://github.com/compute-blade-community/compute-blade-agent/commit/7f166f2ed37af3cf005824a7bb9337e7fff9652d))
* add event-driven handlers ([974db55](https://github.com/compute-blade-community/compute-blade-agent/commit/974db555ffdc920162c445b1748ab08758bd7e80))
* add readme + goreleaser ([29a0e35](https://github.com/compute-blade-community/compute-blade-agent/commit/29a0e35b2c1df0c86574551129684483a0b8bc42))
* add rudimentary API & bladectl client ([7089212](https://github.com/compute-blade-community/compute-blade-agent/commit/70892128bcd8dd9eaf7acb03c9bd14af76d80524))
* add smart fan unit support ([#29](https://github.com/compute-blade-community/compute-blade-agent/issues/29)) ([9992037](https://github.com/compute-blade-community/compute-blade-agent/commit/99920370fba8176dc34243d28281aa343f437fc5))
* **agent:** add support for mTLS authentication in gRPC server ([#54](https://github.com/compute-blade-community/compute-blade-agent/issues/54)) ([70541d8](https://github.com/compute-blade-community/compute-blade-agent/commit/70541d86bad675a153daf8b5c80a92de204502ab))
* **agent:** expose version, commit, and date information in logs for better tracking ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* **bladectl:** implement command structure for managing compute-blade features ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* fan speed detection, edge button events/debouncing ([b32aae0](https://github.com/compute-blade-community/compute-blade-agent/commit/b32aae0ad081198d24c82998ed8f9c69b0fcf038))
* **goreleaser:** add versioning information to builds for better traceability ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* initial commit ([933e44d](https://github.com/compute-blade-community/compute-blade-agent/commit/933e44d1db68f17c90b4aac0188c654c00a2fd6a))
* LedEngine for controlling LED patterns (e.g. burst blinks) ([752d396](https://github.com/compute-blade-community/compute-blade-agent/commit/752d39697e1428c7b9f9c8628d523e2cd3a4dfa7))
* make ws281x work next to PWM based fan speed control ([906f56f](https://github.com/compute-blade-community/compute-blade-agent/commit/906f56fe24c62c3fa0467efd9eeef74f735f2918))
* migrate to uptime-industries gh org ([#37](https://github.com/compute-blade-community/compute-blade-agent/issues/37)) ([6421521](https://github.com/compute-blade-community/compute-blade-agent/commit/6421521bfc94a6211ed084bf8913f413e27e5b14))
* switch to release-please ([#19](https://github.com/compute-blade-community/compute-blade-agent/issues/19)) ([33dd6e5](https://github.com/compute-blade-community/compute-blade-agent/commit/33dd6e5adf45d2b59c1af061c7e78c9426329f15))


### Bug Fixes

* **.gitignore:** add .idea directory to ignore list to prevent IDE files from being tracked ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* ${ -&gt; ${{ ... ([#27](https://github.com/compute-blade-community/compute-blade-agent/issues/27)) ([f2cd029](https://github.com/compute-blade-community/compute-blade-agent/commit/f2cd029d83329085354acb7ed68da390dfe9aee4))
* add debug statement ([#25](https://github.com/compute-blade-community/compute-blade-agent/issues/25)) ([21d9942](https://github.com/compute-blade-community/compute-blade-agent/commit/21d99426293b724f53f0de594fce21e5c49724f8))
* auth to ghcr.io ([#63](https://github.com/compute-blade-community/compute-blade-agent/issues/63)) ([6faf63c](https://github.com/compute-blade-community/compute-blade-agent/commit/6faf63c76f5802540fbf4c677467f5681b87cdd3))
* **bladectl:** improve error handling in identify command for better user feedback ([ec6229a](https://github.com/compute-blade-community/compute-blade-agent/commit/ec6229ad86b4eff06e40c805f8e4f216fe844c18))
* bump github action cache to v3 everywhere ([#17](https://github.com/compute-blade-community/compute-blade-agent/issues/17)) ([7af2623](https://github.com/compute-blade-community/compute-blade-agent/commit/7af26237653ca44772b8c110cccb961adfa77be3))
* bump tinygo release ([#39](https://github.com/compute-blade-community/compute-blade-agent/issues/39)) ([3278678](https://github.com/compute-blade-community/compute-blade-agent/commit/32786787683e2a0cd42b63b92fe7dd2c41bb6e8f))
* change OCI target image ([74c74de](https://github.com/compute-blade-community/compute-blade-agent/commit/74c74dead53bc5b402e2b7489e3c5e8ffd26b720))
* cleanup of gRPC conn is done based on the context ([5129bf6](https://github.com/compute-blade-community/compute-blade-agent/commit/5129bf6b332370f198e1f16ab9bc5532b0f78e95))
* cleanup uf2 files ([d088a1b](https://github.com/compute-blade-community/compute-blade-agent/commit/d088a1ba0a1adba7694a7d2d3b7d49bb9c72fe0c))
* correct package name from computeblade-agent to compute-blade-agent ([#47](https://github.com/compute-blade-community/compute-blade-agent/issues/47)) ([67b3411](https://github.com/compute-blade-community/compute-blade-agent/commit/67b3411e32df10673c5f3bab8b76f31f366cf3ab))
* debug statement ([#26](https://github.com/compute-blade-community/compute-blade-agent/issues/26)) ([780455e](https://github.com/compute-blade-community/compute-blade-agent/commit/780455e749a6acd896ce862ac565f1d1f5467c20))
* explicitly check for true before running goreleaser ([#21](https://github.com/compute-blade-community/compute-blade-agent/issues/21)) ([9c82b60](https://github.com/compute-blade-community/compute-blade-agent/commit/9c82b60fd88718ad90a9a0aa774ffc4bcdd18d3f))
* finalize renaming ([158e7fc](https://github.com/compute-blade-community/compute-blade-agent/commit/158e7fc1bde46e66327d70f87743df39070c2753))
* gha cache for go mod/build ([87f4d42](https://github.com/compute-blade-community/compute-blade-agent/commit/87f4d42b82db742120029f09fceec2cce87da51a))
* gha cache for go mod/build ([#16](https://github.com/compute-blade-community/compute-blade-agent/issues/16)) ([ecf70a4](https://github.com/compute-blade-community/compute-blade-agent/commit/ecf70a4cd068b50c33fe61ff867459134c57c522))
* graceful connection termination when invoking the CLI ([da9eea3](https://github.com/compute-blade-community/compute-blade-agent/commit/da9eea3320d3efd5fbdd295b1f7382f4a4f37f2c))
* graceful connection termination when invoking the CLI ([3001c0f](https://github.com/compute-blade-community/compute-blade-agent/commit/3001c0f4c81340d626feb6ba54b6e65685fab1f7)), closes [#8](https://github.com/compute-blade-community/compute-blade-agent/issues/8)
* if condition ([#22](https://github.com/compute-blade-community/compute-blade-agent/issues/22)) ([cee6912](https://github.com/compute-blade-community/compute-blade-agent/commit/cee6912f5768a310c2758c8755b9ed1985b10d23))
* if statement? ([#23](https://github.com/compute-blade-community/compute-blade-agent/issues/23)) ([4691e2b](https://github.com/compute-blade-community/compute-blade-agent/commit/4691e2b3d71b9c28ebbed31b564c5356713b91f9))
* in-software polling of button presses ([bab60fc](https://github.com/compute-blade-community/compute-blade-agent/commit/bab60fcd78ff589c2c791a8ca4dad2032fdadb48))
* in-software polling of button presses ([b4f9895](https://github.com/compute-blade-community/compute-blade-agent/commit/b4f989546453fb933cbbd26e868cc6d45c29c997))
* LedEngine targeting the same LED, align naming ([edb3fa8](https://github.com/compute-blade-community/compute-blade-agent/commit/edb3fa8b84ae75c2031c27030ad1f96debc388b0))
* login to ghcr, cosign ([b1e8a88](https://github.com/compute-blade-community/compute-blade-agent/commit/b1e8a88210f0de0cdb804d940be7338cc550c546))
* oci reg typo ([3cbf7a8](https://github.com/compute-blade-community/compute-blade-agent/commit/3cbf7a8733dedde834f7392de0851c971a6e3a05))
* pin golang/tinygo versions ([ca690d4](https://github.com/compute-blade-community/compute-blade-agent/commit/ca690d418f099881b6aafdb2ca4be3cee6ac73fc))
* remove debug exit on startup ([0170f70](https://github.com/compute-blade-community/compute-blade-agent/commit/0170f70cc02364c5c092914629b39ca619f36515))
* rename release-please -&gt; release workflow ([#28](https://github.com/compute-blade-community/compute-blade-agent/issues/28)) ([e86b221](https://github.com/compute-blade-community/compute-blade-agent/commit/e86b221aa886f11d6303521787ca4c755b114a6e))
* set goreleaser version to v2.x ([#61](https://github.com/compute-blade-community/compute-blade-agent/issues/61)) ([790ea20](https://github.com/compute-blade-community/compute-blade-agent/commit/790ea2089ab170930d704132eec9b11aaf7fec40))
* set ws281x pin as output, not input ([4542e97](https://github.com/compute-blade-community/compute-blade-agent/commit/4542e970a77843bbaf4694b1be4aa5287124c581))
* smart fan unit improvements ([#31](https://github.com/compute-blade-community/compute-blade-agent/issues/31)) ([a8d470d](https://github.com/compute-blade-community/compute-blade-agent/commit/a8d470d4f9ec2749e1067474805f67639cd24c09))
* while sending 32bits with the FIFO, just 24 are required! :) ([a6495a2](https://github.com/compute-blade-community/compute-blade-agent/commit/a6495a2a4f55fb0a84badc184a18f7ed56bc8eec))


### Miscellaneous Chores

* **go version:** Bump go version to 1.24 ([#58](https://github.com/compute-blade-community/compute-blade-agent/issues/58)) ([ff6898f](https://github.com/compute-blade-community/compute-blade-agent/commit/ff6898f51467cc781b37f5e70b3d8ab198265948))
* more refactoring ([95e2a8d](https://github.com/compute-blade-community/compute-blade-agent/commit/95e2a8d60cf8cdbf62fe184b5df6c35572d2cd11))

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

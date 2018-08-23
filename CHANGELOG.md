# old changes - predating the changelog

Following reverse engineered from the Git log for the last few minor version increments

## Current

* Added a changelog for https://github.com/CultivateHQ/basic_auth/issues/37


## v2.2.2 (2017-12-12)

### Bug fixes

* Guard against timing attacks using `Plug.Crypto.secure_compare/2`

## v2.2.1 (2017-10-26)


### Bug fixes

* Add content type to page response headers from Scott S <scottswezey@users.noreply.github.com>

### Other

* Various refactorings and increasing test coverage

## v2.1.5 (2017-10-04)


### Bug fixes

* Allow passwords to contain a colon, from https://github.com/CultivateHQ/basic_auth/pull/28
* Various documentation fixes
* Invalid basic auth base64 encoding should return a 401 https://github.com/CultivateHQ/basic_auth/pull/24

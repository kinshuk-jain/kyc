### Testing 

#### Philosophy

- We are using pytest for unit and integration tests in this package. 
- While writing your tests, please do not test implementation details.
  - What not to test:
    - checking whether function was called with right parameter names,
    - a particularly named variable was set,
    - a given value was returned,
    - A function was called
    - a module was imported
    - testing internal functions i.e. functions that are not part of public API. Public API means
      functions that are not used by other people or other code
  - What to test:
    - test behavior of modules
    - test behavior of functions
    - test public API

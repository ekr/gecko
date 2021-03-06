// Copyright (C) 2015 the V8 project authors. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
es6id: 9.5.4
description: >
    Trap returns abrupt.
info: >
    [[PreventExtensions]] ( )

    ...
    8. Let booleanTrapResult be ToBoolean(Call(trap, handler, «target»)).
    9. ReturnIfAbrupt(booleanTrapResult).
    ...
---*/

var p = new Proxy({}, {
    preventExtensions: function(t) {
        throw new Test262Error();
    }
});

assert.throws(Test262Error, function() {
    Object.preventExtensions(p);
});

reportCompare(0, 0);

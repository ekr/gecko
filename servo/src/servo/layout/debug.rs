trait BoxedDebugMethods {
    pure fn dump(@self);
    pure fn dump_indent(@self, ident: uint);
    pure fn debug_str(@self) -> ~str;
}

trait DebugMethods {
    pure fn dump(&self);
    pure fn dump_indent(&self, ident: uint);
    pure fn debug_str(&self) -> ~str;
}

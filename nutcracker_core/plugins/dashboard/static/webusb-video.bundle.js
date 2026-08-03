var go = Object.defineProperty;
var Fs = (r) => {
  throw TypeError(r);
};
var To = (r, e, t) => e in r ? go(r, e, { enumerable: !0, configurable: !0, writable: !0, value: t }) : r[e] = t;
var E = (r, e, t) => To(r, typeof e != "symbol" ? e + "" : e, t), Qi = (r, e, t) => e.has(r) || Fs("Cannot " + t);
var a = (r, e, t) => (Qi(r, e, "read from private field"), t ? t.call(r) : e.get(r)), u = (r, e, t) => e.has(r) ? Fs("Cannot add the same private member more than once") : e instanceof WeakSet ? e.add(r) : e.set(r, t), c = (r, e, t, n) => (Qi(r, e, "write to private field"), n ? n.call(r, t) : e.set(r, t), t), L = (r, e, t) => (Qi(r, e, "access private method"), t);
var Vr, jr, qr, nr;
class ye {
  constructor() {
    u(this, Vr);
    u(this, jr);
    u(this, qr);
    u(this, nr, "running");
    E(this, "resolve", (e) => {
      a(this, jr).call(this, e), c(this, nr, "resolved");
    });
    E(this, "reject", (e) => {
      a(this, qr).call(this, e), c(this, nr, "rejected");
    });
    c(this, Vr, new Promise((e, t) => {
      c(this, jr, e), c(this, qr, t);
    }));
  }
  get promise() {
    return a(this, Vr);
  }
  get state() {
    return a(this, nr);
  }
}
Vr = new WeakMap(), jr = new WeakMap(), qr = new WeakMap(), nr = new WeakMap();
class Eo {
  constructor(e = 0) {
    E(this, "nextId");
    E(this, "pendingResolvers", /* @__PURE__ */ new Map());
    this.nextId = e;
  }
  add() {
    const e = this.nextId++, t = new ye();
    return this.pendingResolvers.set(e, t), [e, t.promise];
  }
  getResolver(e) {
    if (!this.pendingResolvers.has(e))
      return null;
    const t = this.pendingResolvers.get(e);
    return this.pendingResolvers.delete(e), t;
  }
  resolve(e, t) {
    const n = this.getResolver(e);
    return n !== null ? (n.resolve(t), !0) : !1;
  }
  reject(e, t) {
    const n = this.getResolver(e);
    return n !== null ? (n.reject(t), !0) : !1;
  }
}
function ha(r) {
  return new Promise((e) => {
    globalThis.setTimeout(() => e(), r);
  });
}
function As(r) {
  return typeof r == "object" && r !== null && "then" in r;
}
function ss(r, e) {
  for (; ; ) {
    const { done: t, value: n } = r.next(e);
    if (t)
      return n;
    if (As(n))
      return n.then((i) => ss(r, { resolved: i }), (i) => ss(r, { error: i }));
    e = n;
  }
}
function me(r) {
  return function(...e) {
    const t = r.call(this, function* (n) {
      if (As(n)) {
        const i = yield n;
        if ("resolved" in i)
          return i.resolved;
        throw i.error;
      }
      return n;
    }, ...e);
    return ss(t, void 0);
  };
}
const pe = new Uint8Array(0), it = function(r, e) {
  return typeof r == "number" ? e ? r === 0 ? {
    size: 0,
    serialize: () => {
    },
    deserialize: () => e.convert(pe)
  } : {
    size: r,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(e.back(t).slice(0, r), i);
    },
    deserialize: me(function* (t, { reader: n }) {
      const i = yield* t(n.readExactly(r));
      return e.convert(i);
    })
  } : r === 0 ? {
    size: 0,
    serialize: () => {
    },
    deserialize: () => pe
  } : {
    size: r,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(t.slice(0, r), i);
    },
    deserialize: ({ reader: t }) => t.readExactly(r)
  } : (typeof r == "object" || typeof r == "function") && "serialize" in r ? e ? {
    size: 0,
    dynamicSize(t) {
      var s;
      const n = e.back(t);
      return (((s = r.dynamicSize) == null ? void 0 : s.call(r, n.length)) ?? r.size) + n.length;
    },
    serialize(t, n) {
      var o;
      const i = e.back(t), s = ((o = r.dynamicSize) == null ? void 0 : o.call(r, i.length)) ?? r.size;
      r.serialize(i.length, n), n.buffer.set(i, n.index + s);
    },
    deserialize: me(function* (t, n) {
      const i = yield* t(r.deserialize(n)), s = yield* t(n.reader.readExactly(i));
      return e.convert(s);
    })
  } : {
    size: 0,
    dynamicSize(t) {
      var i;
      return (((i = r.dynamicSize) == null ? void 0 : i.call(r, t.length)) ?? r.size) + t.length;
    },
    serialize(t, n) {
      var s;
      const i = ((s = r.dynamicSize) == null ? void 0 : s.call(r, t.length)) ?? r.size;
      r.serialize(t.length, n), n.buffer.set(t, n.index + i);
    },
    deserialize: me(function* (t, n) {
      const i = yield* t(r.deserialize(n));
      return n.reader.readExactly(i);
    })
  } : typeof r == "string" ? e ? {
    size: 0,
    preSerialize: (t, n) => {
      n[r] = e.back(t).length;
    },
    dynamicSize: (t) => e.back(t).length,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(e.back(t), i);
    },
    deserialize: me(function* (t, { reader: n, runtimeStruct: i }) {
      const s = i[r];
      if (s === 0)
        return e.convert(pe);
      const o = yield* t(n.readExactly(s));
      return e.convert(o);
    })
  } : {
    size: 0,
    preSerialize: (t, n) => {
      n[r] = t.length;
    },
    dynamicSize: (t) => t.length,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(t, i);
    },
    deserialize: ({ reader: t, runtimeStruct: n }) => {
      const i = n[r];
      return i === 0 ? pe : t.readExactly(i);
    }
  } : e ? {
    size: 0,
    preSerialize: (t, n) => {
      const i = e.back(t).length;
      n[r.field] = r.back(i);
    },
    dynamicSize: (t) => e.back(t).length,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(e.back(t), i);
    },
    deserialize: me(function* (t, { reader: n, runtimeStruct: i }) {
      const s = i[r.field], o = r.convert(s);
      if (o === 0)
        return e.convert(pe);
      const l = yield* t(n.readExactly(o));
      return e.convert(l);
    })
  } : {
    size: 0,
    preSerialize: (t, n) => {
      n[r.field] = r.back(t.length);
    },
    dynamicSize: (t) => t.length,
    serialize: (t, { buffer: n, index: i }) => {
      n.set(t, i);
    },
    deserialize: ({ reader: t, runtimeStruct: n }) => {
      const i = n[r.field], s = r.convert(i);
      return s === 0 ? pe : t.readExactly(s);
    }
  };
};
function So(r, e, t) {
  return t ? (r[e] | r[e + 1] << 8) << 16 >> 16 : (r[e] << 8 | r[e + 1]) << 16 >> 16;
}
function zo(r, e, t, n) {
  n ? (r[e] = t, r[e + 1] = t >> 8) : (r[e] = t >> 8, r[e + 1] = t);
}
function Ao(r, e, t) {
  return t ? r[e] | r[e + 1] << 8 | r[e + 2] << 16 | r[e + 3] << 24 : r[e] << 24 | r[e + 1] << 16 | r[e + 2] << 8 | r[e + 3];
}
function Lo(r, e, t, n) {
  n ? (r[e] = t, r[e + 1] = t >> 8, r[e + 2] = t >> 16, r[e + 3] = t >> 24) : (r[e] = t >> 24, r[e + 1] = t >> 16, r[e + 2] = t >> 8, r[e + 3] = t);
}
function Ro(r, e, t) {
  r[e] = Number(t & 0xffn), r[e + 1] = Number(t >> 8n & 0xffn), r[e + 2] = Number(t >> 16n & 0xffn), r[e + 3] = Number(t >> 24n & 0xffn), r[e + 4] = Number(t >> 32n & 0xffn), r[e + 5] = Number(t >> 40n & 0xffn), r[e + 6] = Number(t >> 48n & 0xffn), r[e + 7] = Number(t >> 56n & 0xffn);
}
function Xo(r, e, t) {
  r[e] = Number(t >> 56n & 0xffn), r[e + 1] = Number(t >> 48n & 0xffn), r[e + 2] = Number(t >> 40n & 0xffn), r[e + 3] = Number(t >> 32n & 0xffn), r[e + 4] = Number(t >> 24n & 0xffn), r[e + 5] = Number(t >> 16n & 0xffn), r[e + 6] = Number(t >> 8n & 0xffn), r[e + 7] = Number(t & 0xffn);
}
function pa(r, e, t) {
  return t ? r[e] | r[e + 1] << 8 : r[e + 1] | r[e] << 8;
}
function ma(r, e, t, n) {
  n ? (r[e] = t, r[e + 1] = t >> 8) : (r[e] = t >> 8, r[e + 1] = t);
}
function fi(r, e) {
  return (r[e] | r[e + 1] << 8 | r[e + 2] << 16 | r[e + 3] << 24) >>> 0;
}
function ya(r, e) {
  return (r[e] << 24 | r[e + 1] << 16 | r[e + 2] << 8 | r[e + 3]) >>> 0;
}
function Co(r, e, t) {
  return t ? (r[e] | r[e + 1] << 8 | r[e + 2] << 16 | r[e + 3] << 24) >>> 0 : (r[e] << 24 | r[e + 1] << 16 | r[e + 2] << 8 | r[e + 3]) >>> 0;
}
function Io(r, e, t) {
  r[e] = t, r[e + 1] = t >> 8, r[e + 2] = t >> 16, r[e + 3] = t >> 24;
}
function Do(r, e, t, n) {
  n ? (r[e] = t, r[e + 1] = t >> 8, r[e + 2] = t >> 16, r[e + 3] = t >> 24) : (r[e] = t >> 24, r[e + 1] = t >> 16, r[e + 2] = t >> 8, r[e + 3] = t);
}
function Ho(r, e) {
  return BigInt(r[e]) << 56n | BigInt(r[e + 1]) << 48n | BigInt(r[e + 2]) << 40n | BigInt(r[e + 3]) << 32n | BigInt(r[e + 4]) << 24n | BigInt(r[e + 5]) << 16n | BigInt(r[e + 6]) << 8n | BigInt(r[e + 7]);
}
function No(r, e, t) {
  return t ? BigInt(r[e]) | BigInt(r[e + 1]) << 8n | BigInt(r[e + 2]) << 16n | BigInt(r[e + 3]) << 24n | BigInt(r[e + 4]) << 32n | BigInt(r[e + 5]) << 40n | BigInt(r[e + 6]) << 48n | BigInt(r[e + 7]) << 56n : BigInt(r[e]) << 56n | BigInt(r[e + 1]) << 48n | BigInt(r[e + 2]) << 40n | BigInt(r[e + 3]) << 32n | BigInt(r[e + 4]) << 24n | BigInt(r[e + 5]) << 16n | BigInt(r[e + 6]) << 8n | BigInt(r[e + 7]);
}
function ko(r, e, t, n) {
  n ? (r[e] = Number(t & 0xffn), r[e + 1] = Number(t >> 8n & 0xffn), r[e + 2] = Number(t >> 16n & 0xffn), r[e + 3] = Number(t >> 24n & 0xffn), r[e + 4] = Number(t >> 32n & 0xffn), r[e + 5] = Number(t >> 40n & 0xffn), r[e + 6] = Number(t >> 48n & 0xffn), r[e + 7] = Number(t >> 56n & 0xffn)) : (r[e] = Number(t >> 56n & 0xffn), r[e + 1] = Number(t >> 48n & 0xffn), r[e + 2] = Number(t >> 40n & 0xffn), r[e + 3] = Number(t >> 32n & 0xffn), r[e + 4] = Number(t >> 24n & 0xffn), r[e + 5] = Number(t >> 16n & 0xffn), r[e + 6] = Number(t >> 8n & 0xffn), r[e + 7] = Number(t & 0xffn));
}
// @__NO_SIDE_EFFECTS__
function hi(r, e, t) {
  const n = () => n;
  return n.size = r, n.serialize = e, n.deserialize = t, n;
}
const Y = /* @__PURE__ */ hi(1, (r, { buffer: e, index: t }) => {
  e[t] = r;
}, me(function* (r, { reader: e }) {
  return (yield* r(e.readExactly(1)))[0];
})), xe = /* @__PURE__ */ hi(2, (r, { buffer: e, index: t, littleEndian: n }) => {
  ma(e, t, r, n);
}, me(function* (r, { reader: e, littleEndian: t }) {
  const n = yield* r(e.readExactly(2));
  return pa(n, 0, t);
})), g = /* @__PURE__ */ hi(4, (r, { buffer: e, index: t, littleEndian: n }) => {
  Do(e, t, r, n);
}, me(function* (r, { reader: e, littleEndian: t }) {
  const n = yield* r(e.readExactly(4));
  return Co(n, 0, t);
})), Oo = /* @__PURE__ */ hi(4, (r, { buffer: e, index: t, littleEndian: n }) => {
  Lo(e, t, r, n);
}, me(function* (r, { reader: e, littleEndian: t }) {
  const n = yield* r(e.readExactly(4));
  return Ao(n, 0, t);
})), je = /* @__PURE__ */ hi(8, (r, { buffer: e, index: t, littleEndian: n }) => {
  ko(e, t, r, n);
}, me(function* (r, { reader: e, littleEndian: t }) {
  const n = yield* r(e.readExactly(8));
  return No(n, 0, t);
}));
class Ui extends Error {
  constructor() {
    super("ExactReadable ended");
  }
}
const { TextEncoder: Mo, TextDecoder: Vo } = globalThis, jo = /* @__PURE__ */ new Mo(), qo = /* @__PURE__ */ new Vo();
// @__NO_SIDE_EFFECTS__
function _t(r) {
  return jo.encode(r);
}
// @__NO_SIDE_EFFECTS__
function Rr(r) {
  return qo.decode(r);
}
// @__NO_SIDE_EFFECTS__
function Uo(r) {
  const e = it(r, {
    convert: Rr,
    back: _t
  });
  return e.as = () => e, e;
}
const qe = Uo;
class ba extends Error {
  constructor(e) {
    super(e);
  }
}
class Bo extends ba {
  constructor() {
    super("The underlying readable was ended before the struct was fully deserialized");
  }
}
class Ls extends ba {
  constructor() {
    super("The underlying readable doesn't contain any more struct");
  }
}
// @__NO_SIDE_EFFECTS__
function M(r, e) {
  const t = Object.entries(r), n = t.reduce((o, [, l]) => o + l.size, 0), i = !!e.littleEndian, s = e.extra ? Object.getOwnPropertyDescriptors(e.extra) : void 0;
  return {
    fields: r,
    size: n,
    extra: e.extra,
    serialize(o, l) {
      var b;
      for (const [h, y] of t)
        h in o && ((b = y.preSerialize) == null || b.call(y, o[h], o));
      const d = t.map(([h, y]) => {
        var v;
        return ((v = y.dynamicSize) == null ? void 0 : v.call(y, o[h])) ?? y.size;
      }), f = d.reduce((h, y) => h + y, 0);
      let p = !1;
      if (l) {
        if (l.length < f)
          throw new Error("Buffer too small");
        p = !0;
      } else
        l = new Uint8Array(f);
      const m = {
        buffer: l,
        index: 0,
        littleEndian: i
      };
      for (const [h, [y, v]] of t.entries())
        v.serialize(o[y], m), m.index += d[h];
      return p ? f : l;
    },
    deserialize: me(function* (o, l) {
      const d = l.position, f = {}, p = {
        reader: l,
        runtimeStruct: f,
        littleEndian: i
      };
      try {
        for (const [m, b] of t)
          f[m] = yield* o(b.deserialize(p));
      } catch (m) {
        throw m instanceof Ui ? l.position === d ? new Ls() : new Bo() : m;
      }
      return s && Object.defineProperties(f, s), e.postDeserialize ? e.postDeserialize.call(f, f) : f;
    })
  };
}
const { AbortController: pi } = globalThis, yt = /* @__PURE__ */ (() => {
  const { ReadableStream: r } = globalThis;
  return r.from || (r.from = function(e) {
    const t = Symbol.asyncIterator in e ? e[Symbol.asyncIterator]() : e[Symbol.iterator]();
    return new r({
      async pull(n) {
        const i = await t.next();
        if (i.done) {
          n.close();
          return;
        }
        n.enqueue(i.value);
      },
      async cancel(n) {
        var i;
        await ((i = t.return) == null ? void 0 : i.call(t, n));
      }
    });
  }), (!r.prototype[Symbol.asyncIterator] || !r.prototype.values) && (r.prototype.values = async function* (e) {
    const t = this.getReader();
    try {
      for (; ; ) {
        const { done: n, value: i } = await t.read();
        if (n)
          return;
        yield i;
      }
    } finally {
      e != null && e.preventCancel || await t.cancel(), t.releaseLock();
    }
  }, r.prototype[Symbol.asyncIterator] = // eslint-disable-next-line @typescript-eslint/unbound-method
  r.prototype.values), r;
})(), { WritableStream: ze, TransformStream: Lr } = globalThis;
class Se extends yt {
  /**
   * Create a new `PushReadableStream` from a source.
   *
   * @param source If `source` returns a `Promise`, the stream will be closed
   * when the `Promise` is resolved, and be errored when the `Promise` is rejected.
   * @param strategy
   */
  constructor(e, t, n) {
    let i, s = !1;
    const o = new pi();
    super({
      start: (l) => {
        const d = e({
          abortSignal: o.signal,
          enqueue: async (f) => {
            if (n == null || n({
              source: "producer",
              operation: "enqueue",
              value: f,
              phase: "start"
            }), o.signal.aborted) {
              n == null || n({
                source: "producer",
                operation: "enqueue",
                value: f,
                phase: "ignored"
              });
              return;
            }
            if (l.desiredSize === null) {
              l.enqueue(f);
              return;
            }
            if (s) {
              s = !1, l.enqueue(f), n == null || n({
                source: "producer",
                operation: "enqueue",
                value: f,
                phase: "complete"
              });
              return;
            }
            if (l.desiredSize <= 0 && (n == null || n({
              source: "producer",
              operation: "enqueue",
              value: f,
              phase: "waiting"
            }), i = new ye(), await i.promise, o.signal.aborted)) {
              n == null || n({
                source: "producer",
                operation: "enqueue",
                value: f,
                phase: "ignored"
              });
              return;
            }
            l.enqueue(f), n == null || n({
              source: "producer",
              operation: "enqueue",
              value: f,
              phase: "complete"
            });
          },
          close() {
            if (n == null || n({
              source: "producer",
              operation: "close",
              explicit: !0,
              phase: "start"
            }), o.signal.aborted) {
              n == null || n({
                source: "producer",
                operation: "close",
                explicit: !0,
                phase: "ignored"
              });
              return;
            }
            l.close(), n == null || n({
              source: "producer",
              operation: "close",
              explicit: !0,
              phase: "complete"
            });
          },
          error(f) {
            n == null || n({
              source: "producer",
              operation: "error",
              explicit: !0,
              phase: "start"
            }), l.error(f), n == null || n({
              source: "producer",
              operation: "error",
              explicit: !0,
              phase: "complete"
            });
          }
        });
        d && "then" in d && d.then(() => {
          n == null || n({
            source: "producer",
            operation: "close",
            explicit: !1,
            phase: "start"
          });
          try {
            l.close(), n == null || n({
              source: "producer",
              operation: "close",
              explicit: !1,
              phase: "complete"
            });
          } catch {
            n == null || n({
              source: "producer",
              operation: "close",
              explicit: !1,
              phase: "ignored"
            });
          }
        }, (f) => {
          n == null || n({
            source: "producer",
            operation: "error",
            explicit: !1,
            phase: "start"
          }), l.error(f), n == null || n({
            source: "producer",
            operation: "error",
            explicit: !1,
            phase: "complete"
          });
        });
      },
      pull: () => {
        n == null || n({
          source: "consumer",
          operation: "pull",
          phase: "start"
        }), i ? i.resolve() : (t == null ? void 0 : t.highWaterMark) === 0 && (s = !0), n == null || n({
          source: "consumer",
          operation: "pull",
          phase: "complete"
        });
      },
      cancel: (l) => {
        n == null || n({
          source: "consumer",
          operation: "cancel",
          phase: "start"
        }), o.abort(l), i == null || i.resolve(), n == null || n({
          source: "consumer",
          operation: "cancel",
          phase: "complete"
        });
      }
    }, t);
  }
}
function Wo(r) {
  try {
    return r.close(), !0;
  } catch {
    return !1;
  }
}
async function Fo(r) {
  try {
    return await r.cancel(), !0;
  } catch {
    return !1;
  }
}
var Be, We, Fe, st, pt, as, os;
class bt {
  constructor(e) {
    u(this, pt);
    u(this, Be);
    // PERF: `subarray` is slow
    // don't use it until absolutely necessary
    u(this, We, 0);
    u(this, Fe, 0);
    u(this, st, 0);
    E(this, "stream");
    E(this, "reader");
    E(this, "readExactly", me(function* (e, t) {
      let n, i = 0;
      const s = L(this, pt, as).call(this, t);
      if (s) {
        if (s.length === t)
          return s;
        n = new Uint8Array(t), n.set(s, i), i += s.length, t -= s.length;
      } else
        n = new Uint8Array(t);
      for (; t > 0; ) {
        const o = yield* e(L(this, pt, os).call(this, t));
        n.set(o, i), i += o.length, t -= o.length;
      }
      return n;
    }));
    this.stream = e, this.reader = e.getReader();
  }
  get position() {
    return a(this, st);
  }
  iterateExactly(e) {
    let t = a(this, Be) ? 0 : 1;
    return {
      next: () => {
        switch (t) {
          case 0: {
            const n = L(this, pt, as).call(this, e);
            return n.length === e ? t = 2 : (e -= n.length, t = 1), { done: !1, value: n };
          }
          case 1:
            return t = 3, {
              done: !1,
              value: L(this, pt, os).call(this, e).then((n) => (n.length === e ? t = 2 : (e -= n.length, t = 1), n))
            };
          case 2:
            return { done: !0, value: void 0 };
          case 3:
            throw new Error("Can't call `next` before previous Promise resolves");
          default:
            throw new Error("unreachable");
        }
      }
    };
  }
  /**
   * Return a readable stream with unconsumed data (if any) and
   * all data from the wrapped stream.
   * @returns A `ReadableStream`
   */
  release() {
    return a(this, Fe) > 0 ? new Se(async (e) => {
      const t = a(this, Be).subarray(a(this, We));
      for (await e.enqueue(t), e.abortSignal.addEventListener("abort", () => {
        Fo(this.reader);
      }); ; ) {
        const { done: n, value: i } = await this.reader.read();
        if (n)
          return;
        await e.enqueue(i);
      }
    }) : (this.reader.releaseLock(), this.stream);
  }
  async cancel(e) {
    await this.reader.cancel(e);
  }
}
Be = new WeakMap(), We = new WeakMap(), Fe = new WeakMap(), st = new WeakMap(), pt = new WeakSet(), as = function(e) {
  if (!a(this, Be))
    return;
  const t = a(this, Be).subarray(a(this, We), a(this, We) + e);
  return a(this, Fe) > e ? (c(this, st, a(this, st) + e), c(this, We, a(this, We) + e), c(this, Fe, a(this, Fe) - e), t) : (c(this, st, a(this, st) + a(this, Fe)), c(this, Be, void 0), c(this, We, 0), c(this, Fe, 0), t);
}, os = async function(e) {
  const { done: t, value: n } = await this.reader.read();
  if (t)
    throw new Ui();
  return n.length > e ? (c(this, Be, n), c(this, We, e), c(this, Fe, n.length - e), c(this, st, a(this, st) + e), n.subarray(0, e)) : (c(this, st, a(this, st) + n.length), n);
};
var Ur, Br;
class Zo {
  constructor(e) {
    u(this, Ur);
    u(this, Br);
    let t;
    const n = new bt(new Se((i) => {
      t = i;
    }));
    c(this, Ur, new yt({
      async pull(i) {
        try {
          const s = await e(n);
          i.enqueue(s);
        } catch (s) {
          if (s instanceof Ls) {
            i.close();
            return;
          }
          throw s;
        }
      },
      cancel: (i) => n.cancel(i)
    })), c(this, Br, new ze({
      async write(i) {
        await t.enqueue(i);
      },
      abort() {
        t.close();
      },
      close() {
        t.close();
      }
    }));
  }
  get readable() {
    return a(this, Ur);
  }
  get writable() {
    return a(this, Br);
  }
}
Ur = new WeakMap(), Br = new WeakMap();
var ir, Ae, Xi, xt, Wr;
class cs {
  constructor() {
    // PERF: rope (concat strings) is faster than `[].join('')`
    u(this, ir, "");
    u(this, Ae, new ye());
    u(this, Xi, new ze({
      write: (e) => {
        c(this, ir, a(this, ir) + e);
      },
      close: () => {
        a(this, Ae).resolve(a(this, ir)), a(this, xt).enqueue(a(this, ir)), a(this, xt).close();
      },
      abort: (e) => {
        a(this, Ae).reject(e), a(this, xt).error(e);
      }
    }));
    u(this, xt);
    u(this, Wr, new yt({
      start: (e) => {
        c(this, xt, e);
      }
    }));
    Object.defineProperties(a(this, Wr), {
      then: {
        get: () => a(this, Ae).promise.then.bind(a(this, Ae).promise)
      },
      catch: {
        get: () => a(this, Ae).promise.catch.bind(a(this, Ae).promise)
      },
      finally: {
        get: () => a(this, Ae).promise.finally.bind(a(this, Ae).promise)
      }
    });
  }
  get writable() {
    return a(this, Xi);
  }
  get readable() {
    return a(this, Wr);
  }
}
ir = new WeakMap(), Ae = new WeakMap(), Xi = new WeakMap(), xt = new WeakMap(), Wr = new WeakMap();
const { console: yi } = globalThis, Go = /* @__PURE__ */ (() => {
  var r;
  return ((r = yi == null ? void 0 : yi.createTask) == null ? void 0 : r.bind(yi)) ?? (() => ({
    run(e) {
      return e();
    }
  }));
})();
let Yo = class extends ze {
  static async write(e, t) {
    const n = new ue(t);
    await e.write(n), await n.consumed;
  }
  constructor(e, t) {
    let n;
    t && (n = {}, "highWaterMark" in t && (n.highWaterMark = t.highWaterMark), "size" in t && (n.size = (i) => t.size(i instanceof ue ? i.value : i))), super({
      start(i) {
        var s;
        return (s = e.start) == null ? void 0 : s.call(e, i);
      },
      async write(i, s) {
        await i.tryConsume((o) => {
          var l;
          return (l = e.write) == null ? void 0 : l.call(e, o, s);
        });
      },
      abort(i) {
        var s;
        return (s = e.abort) == null ? void 0 : s.call(e, i);
      },
      close() {
        var i;
        return (i = e.close) == null ? void 0 : i.call(e);
      }
    }, n);
  }
}, Jo = class wa extends yt {
  static async enqueue(e, t) {
    const n = new ue(t);
    e.enqueue(n), await n.consumed;
  }
  constructor(e, t) {
    let n, i;
    t && (i = {}, "highWaterMark" in t && (i.highWaterMark = t.highWaterMark), "size" in t && (i.size = (s) => t.size(s.value))), super({
      async start(s) {
        var o;
        n = {
          async enqueue(l) {
            await wa.enqueue(s, l);
          },
          close() {
            s.close();
          },
          error(l) {
            s.error(l);
          }
        }, await ((o = e.start) == null ? void 0 : o.call(e, n));
      },
      async pull() {
        var s;
        await ((s = e.pull) == null ? void 0 : s.call(e, n));
      },
      async cancel(s) {
        var o;
        await ((o = e.cancel) == null ? void 0 : o.call(e, s));
      }
    }, i);
  }
};
var Fr, Le;
class ue {
  constructor(e) {
    u(this, Fr);
    u(this, Le);
    E(this, "value");
    E(this, "consumed");
    c(this, Fr, Go("Consumable")), this.value = e, c(this, Le, new ye()), this.consumed = a(this, Le).promise;
  }
  consume() {
    a(this, Le).resolve();
  }
  error(e) {
    a(this, Le).reject(e);
  }
  tryConsume(e) {
    try {
      let t = a(this, Fr).run(() => e(this.value));
      return As(t) ? t = t.then((n) => (a(this, Le).resolve(), n), (n) => {
        throw a(this, Le).reject(n), n;
      }) : a(this, Le).resolve(), t;
    } catch (t) {
      throw a(this, Le).reject(t), t;
    }
  }
}
Fr = new WeakMap(), Le = new WeakMap(), E(ue, "WritableStream", Yo), E(ue, "ReadableStream", Jo);
function va(r, e) {
  return r instanceof ue ? r.tryConsume(e) : e(r);
}
class Bi extends ze {
  constructor(e, t) {
    let n;
    t && (n = {}, "highWaterMark" in t && (n.highWaterMark = t.highWaterMark), "size" in t && (n.size = (i) => t.size(i instanceof ue ? i.value : i))), super({
      start(i) {
        var s;
        return (s = e.start) == null ? void 0 : s.call(e, i);
      },
      async write(i, s) {
        await va(i, (o) => {
          var l;
          return (l = e.write) == null ? void 0 : l.call(e, o, s);
        });
      },
      abort(i) {
        var s;
        return (s = e.abort) == null ? void 0 : s.call(e, i);
      },
      close() {
        var i;
        return (i = e.close) == null ? void 0 : i.call(e);
      }
    }, n);
  }
}
var Ze, Ge, fe, Pe;
class xa {
  constructor(e) {
    u(this, Ze);
    u(this, Ge);
    u(this, fe);
    u(this, Pe);
    c(this, Ze, e), c(this, Ge, new Uint8Array(e)), c(this, fe, 0), c(this, Pe, e);
  }
  /**
   * Pushes data to the combiner.
   * @param data The input data to be split or combined.
   * @returns
   * A generator that yields buffers of specified size.
   * It may yield the same buffer multiple times, consume the data before calling `next`.
   */
  *push(e) {
    let t = 0, n = e.length;
    if (a(this, fe) !== 0)
      if (n >= a(this, Pe)) {
        if (a(this, Ge).set(e.subarray(0, a(this, Pe)), a(this, fe)), t += a(this, Pe), n -= a(this, Pe), yield a(this, Ge), c(this, fe, 0), c(this, Pe, a(this, Ze)), n === 0)
          return;
      } else {
        a(this, Ge).set(e, a(this, fe)), c(this, fe, a(this, fe) + n), c(this, Pe, a(this, Pe) - n);
        return;
      }
    for (; n >= a(this, Ze); ) {
      const i = t + a(this, Ze);
      yield e.subarray(t, i), t = i, n -= a(this, Ze);
    }
    n > 0 && (a(this, Ge).set(e.subarray(t), a(this, fe)), c(this, fe, a(this, fe) + n), c(this, Pe, a(this, Pe) - n));
  }
  flush() {
    if (a(this, fe) === 0)
      return;
    const e = a(this, Ge).subarray(0, a(this, fe));
    return c(this, fe, 0), c(this, Pe, a(this, Ze)), e;
  }
}
Ze = new WeakMap(), Ge = new WeakMap(), fe = new WeakMap(), Pe = new WeakMap();
class Ko extends Lr {
  constructor(e, t = !1) {
    const n = t ? new xa(e) : void 0;
    super({
      async transform(i, s) {
        await va(i, async (o) => {
          if (n)
            for (const l of n.push(o))
              await ue.ReadableStream.enqueue(s, l);
          else {
            let l = 0, d = o.length;
            for (; d > 0; ) {
              const f = l + e;
              await ue.ReadableStream.enqueue(s, o.subarray(l, f)), l = f, d -= e;
            }
          }
        });
      },
      flush(i) {
        if (n) {
          const s = n.flush();
          s && i.enqueue(s);
        }
      }
    });
  }
}
function Qo(r, e) {
  return "start" in r ? r.start(e) : typeof r == "function" ? r(e) : r;
}
var sr;
class _o extends yt {
  constructor(t, n) {
    super({
      start: async (i) => {
        const s = await Qo(t, i);
        this.readable = s, c(this, sr, this.readable.getReader());
      },
      pull: async (i) => {
        var l;
        const { done: s, value: o } = await a(this, sr).read().catch((d) => {
          throw "error" in t && t.error(d), d;
        });
        s ? (i.close(), "close" in t && await ((l = t.close) == null ? void 0 : l.call(t))) : i.enqueue(o);
      },
      cancel: async (i) => {
        var s;
        await a(this, sr).cancel(i), "cancel" in t && await ((s = t.cancel) == null ? void 0 : s.call(t, i));
      }
    }, n);
    E(this, "readable");
    u(this, sr);
  }
}
sr = new WeakMap();
const Zs = () => {
};
var Zr, Gr, Pt, Yr, ar;
class $o {
  constructor(e) {
    u(this, Zr, []);
    u(this, Gr, []);
    u(this, Pt, !1);
    u(this, Yr, new ye());
    u(this, ar);
    c(this, ar, e ?? {});
  }
  get writableClosed() {
    return a(this, Pt);
  }
  get closed() {
    return a(this, Yr).promise;
  }
  wrapReadable(e, t) {
    return new _o({
      start: (n) => (a(this, Zr).push(n), e),
      cancel: async () => {
        await this.close();
      },
      close: async () => {
        await this.dispose();
      }
    }, t);
  }
  createWritable(e) {
    const t = e.getWriter();
    return a(this, Gr).push(t), new ze({
      write: async (n) => {
        await t.write(n);
      },
      abort: async (n) => {
        await t.abort(n), await this.close();
      },
      close: async () => {
        await t.close().catch(Zs), await this.close();
      }
    });
  }
  async close() {
    var e, t;
    if (!a(this, Pt)) {
      c(this, Pt, !0), await ((t = (e = a(this, ar)).close) == null ? void 0 : t.call(e)) !== !1 && await this.dispose();
      for (const n of a(this, Gr))
        n.close().catch(Zs);
    }
  }
  async dispose() {
    var e, t;
    c(this, Pt, !0), a(this, Yr).resolve();
    for (const n of a(this, Zr))
      Wo(n);
    await ((t = (e = a(this, ar)).dispose) == null ? void 0 : t.call(e));
  }
}
Zr = new WeakMap(), Gr = new WeakMap(), Pt = new WeakMap(), Yr = new WeakMap(), ar = new WeakMap();
const ec = globalThis, gi = ec.TextDecoderStream;
class tc extends Lr {
  constructor(e) {
    super({
      transform(t, n) {
        e(t), n.enqueue(t);
      }
    });
  }
}
function rc(r, e) {
  const t = e.writable.getWriter(), n = e.readable.pipeTo(r);
  return new ze({
    async write(i) {
      await t.write(i);
    },
    async close() {
      await t.close(), await n;
    }
  });
}
function* nc(r, e) {
  let t = 0;
  for (; ; ) {
    const n = r.indexOf(e, t);
    if (n === -1)
      return;
    yield r.substring(t, n), t = n + 1;
  }
}
class ic extends Lr {
  constructor(e) {
    super({
      transform(t, n) {
        for (const i of nc(t, e))
          n.enqueue(i);
      }
    });
  }
}
class Pa extends Zo {
  constructor(e) {
    super((t) => e.deserialize(t));
  }
}
var or;
class sc {
  constructor() {
    u(this, or, []);
    this.dispose = this.dispose.bind(this);
  }
  addDisposable(e) {
    return a(this, or).push(e), e;
  }
  dispose() {
    for (const e of a(this, or))
      e.dispose();
    c(this, or, []);
  }
}
or = new WeakMap();
class vi {
  constructor() {
    E(this, "listeners", []);
    E(this, "event", (e, t, ...n) => {
      const i = {
        listener: e,
        thisArg: t,
        args: n
      };
      return this.addEventListener(i);
    });
    this.event = this.event.bind(this);
  }
  addEventListener(e) {
    this.listeners.push(e);
    const t = () => {
      const n = this.listeners.indexOf(e);
      n !== -1 && this.listeners.splice(n, 1);
    };
    return t.dispose = t, t;
  }
  fire(e) {
    for (const t of this.listeners.slice())
      t.listener.apply(t.thisArg, [e, ...t.args]);
  }
  dispose() {
    this.listeners.length = 0;
  }
}
class Rs extends sc {
  constructor(t) {
    super();
    E(this, "adb");
    this.adb = t;
  }
}
const ac = /* @__PURE__ */ M({ version: g }, { littleEndian: !0 }), oc = /* @__PURE__ */ M({
  bpp: g,
  size: g,
  width: g,
  height: g,
  red_offset: g,
  red_length: g,
  blue_offset: g,
  blue_length: g,
  green_offset: g,
  green_length: g,
  alpha_offset: g,
  alpha_length: g,
  data: it("size")
}, { littleEndian: !0 }), cc = /* @__PURE__ */ M({
  bpp: g,
  colorSpace: g,
  size: g,
  width: g,
  height: g,
  red_offset: g,
  red_length: g,
  blue_offset: g,
  blue_length: g,
  green_offset: g,
  green_length: g,
  alpha_offset: g,
  alpha_length: g,
  data: it("size")
}, { littleEndian: !0 });
class ga extends Error {
  constructor(e, t) {
    super(e, t);
  }
}
class lc extends ga {
  constructor(e) {
    super(`Unsupported FrameBuffer version ${e}`);
  }
}
class uc extends ga {
  constructor() {
    super("FrameBuffer is disabled by current app");
  }
}
async function dc(r) {
  const e = await r.createSocket("framebuffer:"), t = new bt(e.readable);
  let n;
  try {
    ({ version: n } = await ac.deserialize(t));
  } catch (i) {
    throw i instanceof Ls ? new uc() : i;
  }
  switch (n) {
    case 1:
      return await oc.deserialize(t);
    case 2:
      return await cc.deserialize(t);
    default:
      throw new lc(n);
  }
}
class fc extends Rs {
  reboot(e = "") {
    return this.adb.createSocketAndWait(`reboot:${e}`);
  }
  bootloader() {
    return this.reboot("bootloader");
  }
  fastboot() {
    return this.reboot("fastboot");
  }
  recovery() {
    return this.reboot("recovery");
  }
  sideload() {
    return this.reboot("sideload");
  }
  /**
   * Reboot to Qualcomm Emergency Download (EDL) Mode.
   *
   * Only works on some Qualcomm devices.
   */
  qualcommEdlMode() {
    return this.reboot("edl");
  }
  powerOff() {
    return this.adb.subprocess.spawnAndWaitLegacy(["reboot", "-p"]);
  }
  powerButton(e = !1) {
    const t = ["input", "keyevent"];
    return e && t.push("--longpress"), t.push("POWER"), this.adb.subprocess.spawnAndWaitLegacy(t);
  }
  /**
   * Reboot to Samsung Odin download mode.
   *
   * Only works on Samsung devices.
   */
  samsungOdin() {
    return this.reboot("download");
  }
}
var gt, Ye;
class Ta {
  constructor(e = !1) {
    u(this, gt);
    u(this, Ye, []);
    c(this, gt, e);
  }
  wait() {
    if (!a(this, gt) && (c(this, gt, !0), a(this, Ye).length === 0))
      return Promise.resolve();
    const e = new ye();
    return a(this, Ye).push(e), e.promise;
  }
  notifyOne() {
    a(this, Ye).length !== 0 ? a(this, Ye).pop().resolve() : c(this, gt, !1);
  }
  dispose() {
    for (const e of a(this, Ye))
      e.reject(new Error("The AutoResetEvent has been disposed"));
    a(this, Ye).length = 0;
  }
}
gt = new WeakMap(), Ye = new WeakMap();
const [Td, K, rr] = /* @__PURE__ */ (() => {
  const r = [], e = [];
  function n(i, s) {
    const o = i.charCodeAt(0), l = s.charCodeAt(0);
    for (let d = o; d <= l; d += 1)
      r[d] = e.length, e.push(d);
  }
  return n("A", "Z"), n("a", "z"), n("0", "9"), n("+", "+"), n("/", "/"), [r, e, 61];
})();
function Ea(r) {
  const e = r % 3, t = e !== 0 ? 3 - e : 0;
  return [(r + t) / 3 * 4, t];
}
function hc(r, e) {
  const [t, n] = Ea(r.length);
  if (e) {
    if (e.length < t)
      throw new TypeError("output buffer is too small");
    if (e = e.subarray(0, t), r.buffer !== e.buffer)
      _i(r, e, n);
    else if (e.byteOffset + e.length - (n + 1) <= r.byteOffset + r.length)
      _i(r, e, n);
    else if (e.byteOffset >= r.byteOffset - 1)
      pc(r, e, n);
    else
      throw new TypeError("input and output cannot overlap");
    return t;
  } else
    return e = new Uint8Array(t), _i(r, e, n), e;
}
function _i(r, e, t) {
  let n = 0, i = 0;
  for (; n < r.length - 2; ) {
    const s = r[n];
    n += 1;
    const o = r[n];
    n += 1;
    const l = r[n];
    n += 1, e[i] = K[s >> 2], i += 1, e[i] = K[(s & 3) << 4 | o >> 4], i += 1, e[i] = K[(o & 15) << 2 | l >> 6], i += 1, e[i] = K[l & 63], i += 1;
  }
  if (t === 2) {
    const s = r[n];
    n += 1, e[i] = K[s >> 2], i += 1, e[i] = K[(s & 3) << 4], i += 1, e[i] = rr, i += 1, e[i] = rr;
  } else if (t === 1) {
    const s = r[n];
    n += 1;
    const o = r[n];
    n += 1, e[i] = K[s >> 2], i += 1, e[i] = K[(s & 3) << 4 | o >> 4], i += 1, e[i] = K[(o & 15) << 2], i += 1, e[i] = rr;
  }
}
function pc(r, e, t) {
  let n = r.length - 1, i = e.length - 1;
  if (t === 2) {
    const s = r[n];
    n -= 1, e[i] = rr, i -= 1, e[i] = rr, i -= 1, e[i] = K[(s & 3) << 4], i -= 1, e[i] = K[s >> 2], i -= 1;
  } else if (t === 1) {
    const s = r[n];
    n -= 1;
    const o = r[n];
    n -= 1, e[i] = rr, i -= 1, e[i] = K[(s & 15) << 2], i -= 1, e[i] = K[(o & 3) << 4 | s >> 4], i -= 1, e[i] = K[o >> 2], i -= 1;
  }
  for (; n >= 0; ) {
    const s = r[n];
    n -= 1;
    const o = r[n];
    n -= 1;
    const l = r[n];
    n -= 1, e[i] = K[s & 63], i -= 1, e[i] = K[(o & 15) << 2 | s >> 6], i -= 1, e[i] = K[(l & 3) << 4 | o >> 4], i -= 1, e[i] = K[l >> 2], i -= 1;
  }
}
function mc(r) {
  if (r < 48)
    throw new TypeError(`Invalid hex char ${r}`);
  if (r < 58)
    return r - 48;
  if (r < 65)
    throw new TypeError(`Invalid hex char ${r}`);
  if (r < 71)
    return r - 55;
  if (r < 97)
    throw new TypeError(`Invalid hex char ${r}`);
  if (r < 103)
    return r - 87;
  throw new TypeError(`Invalid hex char ${r}`);
}
function yc(r) {
  let e = 0;
  for (let t = 0; t < r.length; t += 1)
    e = e << 4 | mc(r[t]);
  return e;
}
const Sa = /* @__NO_SIDE_EFFECTS__ */ () => {
};
function bc(...r) {
  throw new Error(`Unreachable. Arguments:
` + r.join(`
`));
}
function wc(r, e) {
  if (r.length !== e.length)
    return !1;
  for (let t = 0; t < r.length; t += 1)
    if (r[t] !== e[t])
      return !1;
  return !0;
}
const za = /* @__PURE__ */ M({
  length: qe(4),
  content: qe({
    field: "length",
    convert(r) {
      return Number.parseInt(r, 16);
    },
    back(r) {
      return r.toString(16).padStart(4, "0");
    }
  })
}, { littleEndian: !0 });
class Aa extends Error {
  constructor(e) {
    super(e);
  }
}
class Xs extends Aa {
  constructor() {
    super("ADB reverse tunnel is not supported on this device when connected wirelessly.");
  }
}
const vc = /* @__PURE__ */ M(
  za.fields,
  {
    littleEndian: !0,
    postDeserialize: (r) => {
      throw r.content === "more than one device/emulator" ? new Xs() : new Aa(r.content);
    }
  }
);
function xc(r) {
  let e = 0;
  for (const t of r) {
    if (t < 48 || t > 57)
      return e;
    e = e * 10 + t - 48;
  }
  return e;
}
const Pc = /* @__PURE__ */ _t("OKAY");
var cr;
class gc {
  constructor(e) {
    E(this, "adb");
    u(this, cr, /* @__PURE__ */ new Map());
    this.adb = e;
  }
  async createBufferedStream(e) {
    const t = await this.adb.createSocket(e);
    return new bt(t.readable);
  }
  async sendRequest(e) {
    const t = await this.createBufferedStream(e), n = await t.readExactly(4);
    return wc(n, Pc) || await vc.deserialize(t), t;
  }
  /**
   * Get a list of all reverse port forwarding on the device.
   */
  async list() {
    const e = await this.createBufferedStream("reverse:list-forward");
    return (await za.deserialize(e)).content.split(`
`).filter((n) => !!n).map((n) => {
      const [i, s, o] = n.split(" ");
      return { deviceSerial: i, localName: s, remoteName: o };
    });
  }
  /**
   * Add a reverse port forwarding for a program that already listens on a port.
   */
  async addExternal(e, t) {
    const n = await this.sendRequest(`reverse:forward:${e};${t}`);
    if (e.startsWith("tcp:")) {
      const i = n.position;
      try {
        const s = yc(await n.readExactly(4));
        e = `tcp:${xc(await n.readExactly(s))}`;
      } catch (s) {
        if (!(s instanceof Ui && n.position === i)) throw s;
      }
    }
    return e;
  }
  /**
   * Add a reverse port forwarding.
   */
  async add(e, t, n) {
    n = await this.adb.transport.addReverseTunnel(t, n);
    try {
      return e = await this.addExternal(e, n), a(this, cr).set(e, n), e;
    } catch (i) {
      throw await this.adb.transport.removeReverseTunnel(n), i;
    }
  }
  /**
   * Remove a reverse port forwarding.
   */
  async remove(e) {
    const t = a(this, cr).get(e);
    t && await this.adb.transport.removeReverseTunnel(t), await this.sendRequest(`reverse:killforward:${e}`);
  }
  /**
   * Remove all reverse port forwarding, including the ones added by other programs.
   */
  async removeAll() {
    await this.adb.transport.clearReverseTunnels(), a(this, cr).clear(), await this.sendRequest("reverse:killforward-all");
  }
}
cr = new WeakMap();
var at, Jr, Kr;
const Ci = class Ci {
  constructor(e) {
    u(this, at);
    u(this, Jr);
    u(this, Kr);
    c(this, at, e), c(this, Jr, new yt({
      start: async (t) => {
        await a(this, at).closed, t.close();
      }
    })), c(this, Kr, e.closed.then(() => 0));
  }
  static isSupported() {
    return !0;
  }
  static async pty(e, t) {
    return new Ci(await e.createSocket(`shell:${t}`));
  }
  static async raw(e, t) {
    return new Ci(await e.createSocket(`exec:${t}`));
  }
  // Legacy shell forwards all data to stdin.
  get stdin() {
    return a(this, at).writable;
  }
  /**
   * Legacy shell mixes stdout and stderr.
   */
  get stdout() {
    return a(this, at).readable;
  }
  /**
   * `stderr` will always be empty.
   */
  get stderr() {
    return a(this, Jr);
  }
  get exit() {
    return a(this, Kr);
  }
  resize() {
  }
  async kill() {
    await a(this, at).close();
  }
};
at = new WeakMap(), Jr = new WeakMap(), Kr = new WeakMap();
let kr = Ci;
const Q = {
  ShellV2: "shell_v2",
  Cmd: "cmd",
  StatV2: "stat_v2",
  ListV2: "ls_v2",
  FixedPushMkdir: "fixed_push_mkdir",
  Abb: "abb",
  AbbExec: "abb_exec",
  SendReceiveV2: "sendrecv_v2",
  DelayedAck: "delayed_ack"
}, Dr = {
  Stdin: 0,
  Stdout: 1,
  Stderr: 2,
  Exit: 3,
  WindowSizeChange: 5
}, $i = /* @__PURE__ */ M({
  id: Y(),
  data: it(g)
}, { littleEndian: !0 });
var lr, ur, Qr, _r, $r, Tt;
const Ii = class Ii {
  constructor(e) {
    u(this, lr);
    u(this, ur);
    u(this, Qr);
    u(this, _r);
    u(this, $r);
    u(this, Tt, new ye());
    c(this, lr, e);
    let t, n;
    c(this, _r, new Se((i) => {
      t = i;
    })), c(this, $r, new Se((i) => {
      n = i;
    })), e.readable.pipeThrough(new Pa($i)).pipeTo(new ze({
      write: async (i) => {
        switch (i.id) {
          case Dr.Exit:
            a(this, Tt).resolve(i.data[0]);
            break;
          case Dr.Stdout:
            await t.enqueue(i.data);
            break;
          case Dr.Stderr:
            await n.enqueue(i.data);
            break;
        }
      }
    })).then(() => {
      t.close(), n.close(), a(this, Tt).reject(new Error("Socket ended without exit message"));
    }, (i) => {
      t.error(i), n.error(i), a(this, Tt).reject(i);
    }), c(this, ur, a(this, lr).writable.getWriter()), c(this, Qr, new Bi({
      write: async (i) => {
        await a(this, ur).write($i.serialize({
          id: Dr.Stdin,
          data: i
        }));
      }
    }));
  }
  static isSupported(e) {
    return e.canUseFeature(Q.ShellV2);
  }
  static async pty(e, t) {
    return new Ii(await e.createSocket(`shell,v2,pty:${t}`));
  }
  static async raw(e, t) {
    return new Ii(await e.createSocket(`shell,v2,raw:${t}`));
  }
  get stdin() {
    return a(this, Qr);
  }
  get stdout() {
    return a(this, _r);
  }
  get stderr() {
    return a(this, $r);
  }
  get exit() {
    return a(this, Tt).promise;
  }
  async resize(e, t) {
    await a(this, ur).write($i.serialize({
      id: Dr.WindowSizeChange,
      // The "correct" format is `${rows}x${cols},${x_pixels}x${y_pixels}`
      // However, according to https://linux.die.net/man/4/tty_ioctl
      // `x_pixels` and `y_pixels` are unused, so always sending `0` should be fine.
      data: /* @__PURE__ */ _t(`${e}x${t},0x0\0`)
    }));
  }
  kill() {
    return a(this, lr).close();
  }
};
lr = new WeakMap(), ur = new WeakMap(), Qr = new WeakMap(), _r = new WeakMap(), $r = new WeakMap(), Tt = new WeakMap();
let ls = Ii;
const Tc = {
  protocols: [ls, kr]
};
var en, us;
class Ec extends Rs {
  constructor() {
    super(...arguments);
    u(this, en);
  }
  /**
   * Spawns an executable in PTY mode.
   *
   * Redirection mode is enough for most simple commands, but PTY mode is required for
   * commands that manipulate the terminal, such as `vi` and `less`.
   * @param command The command to run. If omitted, the default shell will be spawned.
   * @param options The options for creating the `AdbSubprocessProtocol`
   * @returns A new `AdbSubprocessProtocol` instance connecting to the spawned process.
   */
  shell(t, n) {
    return L(this, en, us).call(this, "pty", t, n);
  }
  /**
   * Spawns an executable and redirect the standard input/output stream.
   *
   * Redirection mode is enough for most simple commands, but PTY mode is required for
   * commands that manipulate the terminal, such as `vi` and `less`.
   * @param command The command to run, or an array of strings containing both command and args.
   * @param options The options for creating the `AdbSubprocessProtocol`
   * @returns A new `AdbSubprocessProtocol` instance connecting to the spawned process.
   */
  spawn(t, n) {
    return L(this, en, us).call(this, "raw", t, n);
  }
  /**
   * Spawns a new process, waits until it exits, and returns the entire output.
   * @param command The command to run
   * @param options The options for creating the `AdbSubprocessProtocol`
   * @returns The entire output of the command
   */
  async spawnAndWait(t, n) {
    const i = await this.spawn(t, n), [s, o, l] = await Promise.all([
      i.stdout.pipeThrough(new gi()).pipeThrough(new cs()),
      i.stderr.pipeThrough(new gi()).pipeThrough(new cs()),
      i.exit
    ]);
    return {
      stdout: s,
      stderr: o,
      exitCode: l
    };
  }
  /**
   * Spawns a new process, waits until it exits, and returns the entire output.
   * @param command The command to run
   * @returns The entire output of the command
   */
  async spawnAndWaitLegacy(t) {
    const { stdout: n } = await this.spawnAndWait(t, {
      protocols: [kr]
    });
    return n;
  }
}
en = new WeakSet(), us = async function(t, n, i) {
  const { protocols: s } = { ...Tc, ...i };
  let o;
  for (const l of s)
    if (await l.isSupported(this.adb)) {
      o = l;
      break;
    }
  if (!o)
    throw new Error("No specified protocol is supported by the device");
  return Array.isArray(n) ? n = n.join(" ") : n === void 0 && (n = ""), await o[t](this.adb, n);
};
function ds(r) {
  let e = "";
  e += "'";
  let t = 0;
  for (; ; ) {
    const n = r.indexOf("'", t);
    if (n === -1) {
      e += r.substring(t);
      break;
    }
    e += r.substring(t, n), e += String.raw`'\''`, t = n + 1;
  }
  return e += "'", e;
}
function Sc(r) {
  const e = new Uint8Array(r.length);
  for (let t = 0; t < r.length; t += 1)
    e[t] = r.charCodeAt(t);
  return e;
}
// @__NO_SIDE_EFFECTS__
function U(r) {
  const e = Sc(r);
  return fi(e, 0);
}
const Ee = {
  Entry: /* @__PURE__ */ U("DENT"),
  Entry2: /* @__PURE__ */ U("DNT2"),
  Lstat: /* @__PURE__ */ U("STAT"),
  Stat: /* @__PURE__ */ U("STA2"),
  Lstat2: /* @__PURE__ */ U("LST2"),
  Done: /* @__PURE__ */ U("DONE"),
  Data: /* @__PURE__ */ U("DATA"),
  Ok: /* @__PURE__ */ U("OKAY"),
  Fail: /* @__PURE__ */ U("FAIL")
};
class zc extends Error {
}
const La = /* @__PURE__ */ M({ message: qe(g) }, {
  littleEndian: !0,
  postDeserialize(r) {
    throw new zc(r.message);
  }
});
async function Ti(r, e, t) {
  typeof e == "string" && (e = /* @__PURE__ */ U(e));
  const n = await r.readExactly(4);
  switch (fi(n, 0)) {
    case Ee.Fail:
      throw await La.deserialize(r), new Error("Unreachable");
    case e:
      return await t.deserialize(r);
    default:
      throw new Error(`Expected '${e}', but got '${/* @__PURE__ */ Rr(n)}'`);
  }
}
async function* Ei(r, e, t) {
  for (typeof e == "string" && (e = /* @__PURE__ */ U(e)); ; ) {
    const n = await r.readExactly(4);
    switch (fi(n, 0)) {
      case Ee.Fail:
        throw await La.deserialize(r), new Error("Unreachable");
      case Ee.Done:
        await r.readExactly(t.size);
        return;
      case e:
        yield await t.deserialize(r);
        break;
      default:
        throw new Error(`Expected '${e}' or '${Ee.Done}', but got '${/* @__PURE__ */ Rr(n)}'`);
    }
  }
}
const De = {
  List: /* @__PURE__ */ U("LIST"),
  ListV2: /* @__PURE__ */ U("LIS2"),
  Send: /* @__PURE__ */ U("SEND"),
  SendV2: /* @__PURE__ */ U("SND2"),
  Lstat: /* @__PURE__ */ U("STAT"),
  Stat: /* @__PURE__ */ U("STA2"),
  LstatV2: /* @__PURE__ */ U("LST2"),
  Data: /* @__PURE__ */ U("DATA"),
  Done: /* @__PURE__ */ U("DONE"),
  Receive: /* @__PURE__ */ U("RECV")
}, Gs = /* @__PURE__ */ M({ id: g, arg: g }, { littleEndian: !0 });
async function Ue(r, e, t) {
  if (typeof e == "string" && (e = /* @__PURE__ */ U(e)), typeof t == "number") {
    await r.write(Gs.serialize({ id: e, arg: t }));
    return;
  }
  typeof t == "string" && (t = /* @__PURE__ */ _t(t)), await r.write(Gs.serialize({ id: e, arg: t.length })), await r.write(t);
}
const Ra = {
  File: 8
}, fs = /* @__PURE__ */ M({ mode: g, size: g, mtime: g }, {
  littleEndian: !0,
  extra: {
    get type() {
      return this.mode >> 12;
    },
    get permission() {
      return this.mode & 4095;
    }
  },
  postDeserialize(r) {
    if (r.mode === 0 && r.size === 0 && r.mtime === 0)
      throw new Error("lstat error");
    return r;
  }
}), Xa = {
  SUCCESS: 0,
  EACCES: 13,
  EEXIST: 17,
  EFAULT: 14,
  EFBIG: 27,
  EINTR: 4,
  EINVAL: 22,
  EIO: 5,
  EISDIR: 21,
  ELOOP: 40,
  EMFILE: 24,
  ENAMETOOLONG: 36,
  ENFILE: 23,
  ENOENT: 2,
  ENOMEM: 12,
  ENOSPC: 28,
  ENOTDIR: 20,
  EOVERFLOW: 75,
  EPERM: 1,
  EROFS: 30,
  ETXTBSY: 26
}, Ac = Object.fromEntries(Object.entries(Xa).map(([r, e]) => [
  e,
  r
])), Si = /* @__PURE__ */ M({
  error: g(),
  dev: je,
  ino: je,
  mode: g,
  nlink: g,
  uid: g,
  gid: g,
  size: je,
  atime: je,
  mtime: je,
  ctime: je
}, {
  littleEndian: !0,
  extra: {
    get type() {
      return this.mode >> 12;
    },
    get permission() {
      return this.mode & 4095;
    }
  },
  postDeserialize(r) {
    if (r.error)
      throw new Error(Ac[r.error]);
    return r;
  }
});
async function Lc(r, e, t) {
  const n = await r.lock();
  try {
    if (t)
      return await Ue(n, De.LstatV2, e), await Ti(n, Ee.Lstat2, Si);
    {
      await Ue(n, De.Lstat, e);
      const i = await Ti(n, Ee.Lstat, fs);
      return {
        mode: i.mode,
        // Convert to `BigInt` to make it compatible with `AdbSyncStatResponse`
        size: BigInt(i.size),
        mtime: BigInt(i.mtime),
        get type() {
          return i.type;
        },
        get permission() {
          return i.permission;
        }
      };
    }
  } finally {
    n.release();
  }
}
async function Rc(r, e) {
  const t = await r.lock();
  try {
    return await Ue(t, De.Stat, e), await Ti(t, Ee.Stat, Si);
  } finally {
    t.release();
  }
}
const Xc = /* @__PURE__ */ M({
  ...fs.fields,
  name: qe(g)
}, { littleEndian: !0, extra: fs.extra }), Cc = /* @__PURE__ */ M({
  ...Si.fields,
  name: qe(g)
}, { littleEndian: !0, extra: Si.extra });
async function* Ic(r, e) {
  const t = await r.lock();
  try {
    await Ue(t, De.ListV2, e);
    for await (const n of Ei(t, Ee.Entry2, Cc))
      n.error === Xa.SUCCESS && (yield n);
  } finally {
    t.release();
  }
}
async function* Dc(r, e) {
  const t = await r.lock();
  try {
    await Ue(t, De.List, e);
    for await (const n of Ei(t, Ee.Entry, Xc))
      yield n;
  } finally {
    t.release();
  }
}
async function* Hc(r, e, t) {
  if (t)
    yield* Ic(r, e);
  else
    for await (const n of Dc(r, e))
      yield {
        mode: n.mode,
        size: BigInt(n.size),
        mtime: BigInt(n.mtime),
        get type() {
          return n.type;
        },
        get permission() {
          return n.permission;
        },
        name: n.name
      };
}
const Ys = /* @__PURE__ */ M({ data: it(g) }, { littleEndian: !0 });
async function* Nc(r, e) {
  const t = await r.lock();
  let n = !1;
  try {
    await Ue(t, De.Receive, e);
    for await (const i of Ei(t, Ee.Data, Ys))
      yield i.data;
    n = !0;
  } catch (i) {
    throw n = !0, i;
  } finally {
    if (!n)
      for await (const i of Ei(t, Ee.Data, Ys))
        ;
    t.release();
  }
}
function kc(r, e) {
  return new Se(async (t) => {
    for await (const n of Nc(r, e))
      await t.enqueue(n);
  });
}
const Ca = 64 * 1024, Oc = /* @__PURE__ */ M({ unused: g }, { littleEndian: !0 });
async function Ia(r, e, t, n) {
  const i = new pi();
  e.pipeThrough(new Ko(t, !0)).pipeTo(new Bi({
    write(s) {
      return Ue(r, De.Data, s);
    }
  }), { signal: i.signal }).then(async () => {
    await Ue(r, De.Done, n), await r.flush();
  }, Sa), await Ti(r, Ee.Ok, Oc).catch((s) => {
    throw i.abort(), s;
  });
}
async function Mc({ socket: r, filename: e, file: t, type: n = Ra.File, permission: i = 438, mtime: s = Date.now() / 1e3 | 0, packetSize: o = Ca }) {
  const l = await r.lock();
  try {
    const d = n << 12 | i, f = `${e},${d.toString()}`;
    await Ue(l, De.Send, f), await Ia(l, t, o, s);
  } finally {
    l.release();
  }
}
const Js = {
  None: 0,
  Brotli: 1,
  /**
   * 2
   */
  Lz4: 2,
  /**
   * 4
   */
  Zstd: 4,
  DryRun: 2147483648
}, Vc = /* @__PURE__ */ M({ id: g, mode: g, flags: g() }, { littleEndian: !0 });
async function jc({ socket: r, filename: e, file: t, type: n = Ra.File, permission: i = 438, mtime: s = Date.now() / 1e3 | 0, packetSize: o = Ca, dryRun: l = !1 }) {
  const d = await r.lock();
  try {
    await Ue(d, De.SendV2, e);
    const f = n << 12 | i;
    let p = Js.None;
    l && (p |= Js.DryRun), await d.write(Vc.serialize({
      id: De.SendV2,
      mode: f,
      flags: p
    })), await Ia(d, t, o, s);
  } finally {
    d.release();
  }
}
function qc(r) {
  if (r.v2)
    return jc(r);
  if (r.dryRun)
    throw new Error("dryRun is not supported in v1");
  return Mc(r);
}
var tn, Et, rn, St, zt, nn, hs;
class Uc {
  constructor(e, t, n, i) {
    u(this, nn);
    u(this, tn);
    u(this, Et);
    u(this, rn);
    u(this, St, new Ta());
    u(this, zt);
    c(this, tn, e), c(this, Et, t), c(this, rn, i), c(this, zt, new xa(n));
  }
  get position() {
    return a(this, Et).position;
  }
  async flush() {
    try {
      await a(this, St).wait();
      const e = a(this, zt).flush();
      e && await L(this, nn, hs).call(this, e);
    } finally {
      a(this, St).notifyOne();
    }
  }
  async write(e) {
    try {
      await a(this, St).wait();
      for (const t of a(this, zt).push(e))
        await L(this, nn, hs).call(this, t);
    } finally {
      a(this, St).notifyOne();
    }
  }
  async readExactly(e) {
    return await this.flush(), await a(this, Et).readExactly(e);
  }
  release() {
    a(this, zt).flush(), a(this, rn).notifyOne();
  }
  async close() {
    await a(this, Et).cancel();
  }
}
tn = new WeakMap(), Et = new WeakMap(), rn = new WeakMap(), St = new WeakMap(), zt = new WeakMap(), nn = new WeakSet(), hs = function(e) {
  return ue.WritableStream.write(a(this, tn), e);
};
var sn, an, dr;
class Bc {
  constructor(e, t) {
    u(this, sn, new Ta());
    u(this, an);
    u(this, dr);
    c(this, an, e), c(this, dr, new Uc(e.writable.getWriter(), new bt(e.readable), t, a(this, sn)));
  }
  async lock() {
    return await a(this, sn).wait(), a(this, dr);
  }
  async close() {
    await a(this, dr).close(), await a(this, an).close();
  }
}
sn = new WeakMap(), an = new WeakMap(), dr = new WeakMap();
function Wc(r) {
  const e = r.lastIndexOf("/");
  if (e === -1)
    throw new Error("Invalid path");
  return e === 0 ? "/" : r.substring(0, e);
}
var At, on, cn, ln, un;
class Fc {
  constructor(e, t) {
    E(this, "_adb");
    E(this, "_socket");
    u(this, At);
    u(this, on);
    u(this, cn);
    u(this, ln);
    u(this, un);
    this._adb = e, this._socket = new Bc(t, e.maxPayloadSize), c(this, At, e.canUseFeature(Q.StatV2)), c(this, on, e.canUseFeature(Q.ListV2)), c(this, cn, e.canUseFeature(Q.FixedPushMkdir)), c(this, ln, e.canUseFeature(Q.SendReceiveV2)), c(this, un, this._adb.canUseFeature(Q.ShellV2) && !this.fixedPushMkdir);
  }
  get supportsStat() {
    return a(this, At);
  }
  get supportsListV2() {
    return a(this, on);
  }
  get fixedPushMkdir() {
    return a(this, cn);
  }
  get supportsSendReceiveV2() {
    return a(this, ln);
  }
  get needPushMkdirWorkaround() {
    return a(this, un);
  }
  /**
   * Gets information of a file or folder.
   *
   * If `path` points to a symbolic link, the returned information is about the link itself (with `type` being `LinuxFileType.Link`).
   */
  async lstat(e) {
    return await Lc(this._socket, e, a(this, At));
  }
  /**
   * Gets the information of a file or folder.
   *
   * If `path` points to a symbolic link, it will be resolved and the returned information is about the target (with `type` being `LinuxFileType.File` or `LinuxFileType.Directory`).
   */
  async stat(e) {
    if (!a(this, At))
      throw new Error("Not supported");
    return await Rc(this._socket, e);
  }
  /**
   * Checks if `path` is a directory, or a symbolic link to a directory.
   *
   * This uses `lstat` internally, thus works on all Android versions.
   */
  async isDirectory(e) {
    try {
      return await this.lstat(e + "/"), !0;
    } catch {
      return !1;
    }
  }
  opendir(e) {
    return Hc(this._socket, e, this.supportsListV2);
  }
  async readdir(e) {
    const t = [];
    for await (const n of this.opendir(e))
      t.push(n);
    return t;
  }
  /**
   * Reads the content of a file on device.
   *
   * @param filename The full path of the file on device to read.
   * @returns A `ReadableStream` that contains the file content.
   */
  read(e) {
    return kc(this._socket, e);
  }
  /**
   * Writes a file on device. If the file name already exists, it will be overwritten.
   *
   * @param options The content and options of the file to write.
   */
  async write(e) {
    this.needPushMkdirWorkaround && await this._adb.subprocess.spawnAndWait([
      "mkdir",
      "-p",
      ds(Wc(e.filename))
    ]), await qc({
      v2: this.supportsSendReceiveV2,
      socket: this._socket,
      ...e
    });
  }
  lockSocket() {
    return this._socket.lock();
  }
  dispose() {
    return this._socket.close();
  }
}
At = new WeakMap(), on = new WeakMap(), cn = new WeakMap(), ln = new WeakMap(), un = new WeakMap();
function Ks(r) {
  if (!(!r || r === "0"))
    return Number.parseInt(r, 10);
}
class Zc extends Rs {
  async getListenAddresses() {
    const e = await this.adb.getProp("service.adb.listen_addrs"), t = await this.adb.getProp("service.adb.tcp.port"), n = await this.adb.getProp("persist.adb.tcp.port");
    return {
      serviceListenAddresses: e != "" ? e.split(",") : [],
      servicePort: Ks(t),
      persistPort: Ks(n)
    };
  }
  async setPort(e) {
    if (e <= 0)
      throw new TypeError(`Invalid port ${e}`);
    const t = await this.adb.createSocketAndWait(`tcpip:${e}`);
    if (t !== `restarting in TCP mode port: ${e}
`)
      throw new Error(t);
    return t;
  }
  async disable() {
    const e = await this.adb.createSocketAndWait("usb:");
    if (e !== `restarting in USB mode
`)
      throw new Error(e);
    return e;
  }
}
class Gc {
  constructor(e) {
    E(this, "transport");
    E(this, "subprocess");
    E(this, "power");
    E(this, "reverse");
    E(this, "tcpip");
    this.transport = e, this.subprocess = new Ec(this), this.power = new fc(this), this.reverse = new gc(this), this.tcpip = new Zc(this);
  }
  get serial() {
    return this.transport.serial;
  }
  get maxPayloadSize() {
    return this.transport.maxPayloadSize;
  }
  get banner() {
    return this.transport.banner;
  }
  get disconnected() {
    return this.transport.disconnected;
  }
  get clientFeatures() {
    return this.transport.clientFeatures;
  }
  get deviceFeatures() {
    return this.banner.features;
  }
  canUseFeature(e) {
    return this.clientFeatures.includes(e) && this.deviceFeatures.includes(e);
  }
  /**
   * Creates a new ADB Socket to the specified service or socket address.
   */
  async createSocket(e) {
    return this.transport.connect(e);
  }
  async createSocketAndWait(e) {
    return await (await this.createSocket(e)).readable.pipeThrough(new gi()).pipeThrough(new cs());
  }
  async getProp(e) {
    return (await this.subprocess.spawnAndWaitLegacy([
      "getprop",
      e
    ])).trim();
  }
  async rm(e, t) {
    const n = ["rm"];
    if (t != null && t.recursive && n.push("-r"), t != null && t.force && n.push("-f"), Array.isArray(e))
      for (const s of e)
        n.push(ds(s));
    else
      n.push(ds(e));
    return n.push("</dev/null"), await this.subprocess.spawnAndWaitLegacy(n);
  }
  async sync() {
    const e = await this.createSocket("sync:");
    return new Fc(this, e);
  }
  async framebuffer() {
    return dc(this);
  }
  async close() {
    await this.transport.close();
  }
}
const bi = {
  Product: "ro.product.name",
  Model: "ro.product.model",
  Device: "ro.product.device",
  Features: "features"
};
var dn, fn, hn, pn;
const ks = class ks {
  constructor(e, t, n, i) {
    u(this, dn);
    u(this, fn);
    u(this, hn);
    u(this, pn, []);
    c(this, dn, e), c(this, fn, t), c(this, hn, n), c(this, pn, i);
  }
  static parse(e) {
    let t, n, i, s = [];
    const o = e.split("::");
    if (o.length > 1) {
      const l = o[1];
      for (const d of l.split(";")) {
        if (!d)
          continue;
        const f = d.split("=");
        if (f.length !== 2)
          continue;
        const [p, m] = f;
        switch (p) {
          case bi.Product:
            t = m;
            break;
          case bi.Model:
            n = m;
            break;
          case bi.Device:
            i = m;
            break;
          case bi.Features:
            s = m.split(",");
            break;
        }
      }
    }
    return new ks(t, n, i, s);
  }
  get product() {
    return a(this, dn);
  }
  get model() {
    return a(this, fn);
  }
  get device() {
    return a(this, hn);
  }
  get features() {
    return a(this, pn);
  }
};
dn = new WeakMap(), fn = new WeakMap(), hn = new WeakMap(), pn = new WeakMap();
let ps = ks;
function ms(r, e, t) {
  let n = 0n;
  for (let i = e; i < e + t; i += 8) {
    n <<= 64n;
    const s = Ho(r, i);
    n |= s;
  }
  return n;
}
function ys(r, e, t, n, i) {
  if (i)
    for (; n > 0n; )
      Ro(r, e, n), e += 8, n >>= 64n;
  else {
    let s = e + t - 8;
    for (; n > 0n; )
      Xo(r, s, n), s -= 8, n >>= 64n;
  }
}
const Yc = 38, Jc = 2048 / 8, Kc = 303, Qc = 2048 / 8;
function Da(r) {
  const e = ms(r, Yc, Jc), t = ms(r, Kc, Qc);
  return [e, t];
}
function Qs(r, e) {
  const t = r % e;
  return t > 0 ? t : t + e;
}
function _c(r, e) {
  if (r = Qs(r, e), !r || e < 2)
    return NaN;
  const t = [];
  let n = e;
  for (; n; )
    [r, n] = [n, r % n], t.push({ a: r, b: n });
  if (r !== 1)
    return NaN;
  let i = 1, s = 0;
  for (let o = t.length - 2; o >= 0; o -= 1)
    [i, s] = [s, i - s * Math.floor(t[o].a / t[o].b)];
  return Qs(s, e);
}
const wt = 2048 / 8, $c = wt / 4;
function Ha() {
  return 8 + wt + wt + 4;
}
function el(r, e) {
  let t;
  const n = Ha();
  if (!e)
    e = new Uint8Array(n), t = "Uint8Array";
  else {
    if (e.length < n)
      throw new TypeError("output buffer is too small");
    t = "number";
  }
  const i = new DataView(e.buffer, e.byteOffset, e.length);
  let s = 0;
  i.setUint32(s, $c, !0), s += 4;
  const [o] = Da(r), l = -_c(Number(o % 2n ** 32n), 2 ** 32);
  i.setInt32(s, l, !0), s += 4, ys(e, s, wt, o, !0), s += wt;
  const d = 2n ** 4096n % o;
  return ys(e, s, wt, d, !0), s += wt, i.setUint32(s, 65537, !0), s += 4, t === "Uint8Array" ? e : n;
}
function tl(r, e, t) {
  if (t === 1n)
    return 0n;
  let n = 1n;
  for (r = r % t; e > 0n; )
    BigInt.asUintN(1, e) === 1n && (n = n * r % t), r = r * r % t, e >>= 1n;
  return n;
}
const _s = 20, $s = 48, rl = 4, nl = 5, il = 6, es = new Uint8Array([
  $s,
  13 + _s,
  $s,
  9,
  // SHA-1 (1 3 14 3 2 26)
  il,
  5,
  1 * 40 + 3,
  14,
  3,
  2,
  26,
  nl,
  0,
  rl,
  _s
]);
function sl(r, e) {
  const [t, n] = Da(r), i = new Uint8Array(256);
  let s = 0;
  i[s] = 0, s += 1, i[s] = 1, s += 1;
  const o = i.length - es.length - e.length - 1;
  for (; s < o; )
    i[s] = 255, s += 1;
  i[s] = 0, s += 1, i.set(es, s), s += es.length, i.set(e, s);
  const l = tl(ms(i, 0, i.length), n, t);
  return ys(i, 0, i.length, l, !1), i;
}
const oe = {
  Auth: 1213486401,
  // 'AUTH'
  Close: 1163086915,
  // 'CLSE'
  Connect: 1314410051,
  // 'CNXN'
  Okay: 1497451343,
  // 'OKAY'
  Open: 1313165391,
  // 'OPEN'
  Write: 1163154007
  // 'WRTE'
}, bs = /* @__PURE__ */ M({
  command: g,
  arg0: g,
  arg1: g,
  payloadLength: g,
  checksum: g,
  magic: Oo
}, { littleEndian: !0 });
function Na(r) {
  return r.reduce((e, t) => e + t, 0);
}
class al extends Lr {
  constructor() {
    const e = new Uint8Array(bs.size);
    super({
      transform: async (t, n) => {
        await t.tryConsume(async (i) => {
          const s = i;
          s.payloadLength = s.payload.length, bs.serialize(s, e), await ue.ReadableStream.enqueue(n, e), s.payloadLength && await ue.ReadableStream.enqueue(n, s.payload);
        });
      }
    });
  }
}
const zi = {
  Token: 1,
  Signature: 2,
  PublicKey: 3
}, ol = async function* (r, e) {
  for await (const t of r.iterateKeys()) {
    const n = await e();
    if (n.arg0 !== zi.Token)
      return;
    const i = sl(t.buffer, n.payload);
    yield {
      command: oe.Auth,
      arg0: zi.Signature,
      arg1: 0,
      payload: i
    };
  }
}, cl = async function* (r, e) {
  var d;
  if ((await e()).arg0 !== zi.Token)
    return;
  let n;
  for await (const f of r.iterateKeys()) {
    n = f;
    break;
  }
  n || (n = await r.generateKey());
  const i = Ha(), [s] = Ea(i), o = (d = n.name) != null && d.length ? /* @__PURE__ */ _t(n.name) : pe, l = new Uint8Array(s + (o.length ? o.length + 1 : 0) + // Space character + name
  1);
  el(n.buffer, l), hc(l.subarray(0, i), l), o.length && (l[s] = 32, l.set(o, s + 1)), yield {
    command: oe.Auth,
    arg0: zi.PublicKey,
    arg1: 0,
    payload: l
  };
}, ll = [
  ol,
  cl
];
var mn, fr, Lt, Di, Hi, ka;
class ul {
  constructor(e, t) {
    u(this, Hi);
    E(this, "authenticators");
    u(this, mn);
    u(this, fr, new ye());
    u(this, Lt);
    u(this, Di, () => a(this, fr).promise);
    this.authenticators = e, c(this, mn, t);
  }
  async process(e) {
    a(this, Lt) || c(this, Lt, L(this, Hi, ka).call(this)), a(this, fr).resolve(e);
    const t = await a(this, Lt).next();
    if (t.done)
      throw new Error("No authenticator can handle the request");
    return t.value;
  }
  dispose() {
    var e, t;
    (t = (e = a(this, Lt)) == null ? void 0 : e.return) == null || t.call(e);
  }
}
mn = new WeakMap(), fr = new WeakMap(), Lt = new WeakMap(), Di = new WeakMap(), Hi = new WeakSet(), ka = async function* () {
  for (const e of this.authenticators)
    for await (const t of e(a(this, mn), a(this, Di)))
      c(this, fr, new ye()), yield t;
};
var Rt, yn, hr, bn, wn, vn, xn, Xt, Je, Ni, Oa;
class ea {
  constructor(e) {
    u(this, Ni);
    u(this, Rt);
    E(this, "localId");
    E(this, "remoteId");
    E(this, "localCreated");
    E(this, "service");
    u(this, yn);
    u(this, hr);
    u(this, bn);
    E(this, "writable");
    u(this, wn, !1);
    u(this, vn, new ye());
    u(this, xn);
    u(this, Xt);
    /**
     * When delayed ack is disabled, returns `Infinity` if the socket is ready to write
     * (exactly one packet can be written no matter how large it is), or `-1` if the socket
     * is waiting for ack message.
     *
     * When delayed ack is enabled, returns a non-negative finite number indicates the number of
     * bytes that can be written to the socket before waiting for ack message.
     */
    u(this, Je, 0);
    c(this, Rt, e.dispatcher), this.localId = e.localId, this.remoteId = e.remoteId, this.localCreated = e.localCreated, this.service = e.service, c(this, yn, new Se((t) => {
      c(this, hr, t);
    })), this.writable = new Bi({
      start: (t) => {
        c(this, bn, t), t.signal.addEventListener("abort", () => {
          var n;
          (n = a(this, Xt)) == null || n.reject(t.signal.reason);
        });
      },
      write: async (t) => {
        const n = t.length, i = a(this, Rt).options.maxPayloadSize;
        for (let s = 0, o = i; s < n; s = o, o += i) {
          const l = t.subarray(s, o);
          await L(this, Ni, Oa).call(this, l);
        }
      }
    }), c(this, xn, new dl(this)), c(this, Je, e.availableWriteBytes);
  }
  get readable() {
    return a(this, yn);
  }
  get closed() {
    return a(this, vn).promise;
  }
  get socket() {
    return a(this, xn);
  }
  async enqueue(e) {
    await a(this, hr).enqueue(e);
  }
  ack(e) {
    var t;
    c(this, Je, a(this, Je) + e), (t = a(this, Xt)) == null || t.resolve();
  }
  async close() {
    var e;
    if (!a(this, wn)) {
      c(this, wn, !0), (e = a(this, Xt)) == null || e.reject(new Error("Socket closed"));
      try {
        a(this, bn).error(new Error("Socket closed"));
      } catch {
      }
      await a(this, Rt).sendPacket(oe.Close, this.localId, this.remoteId, pe);
    }
  }
  dispose() {
    a(this, hr).close(), a(this, vn).resolve();
  }
}
Rt = new WeakMap(), yn = new WeakMap(), hr = new WeakMap(), bn = new WeakMap(), wn = new WeakMap(), vn = new WeakMap(), xn = new WeakMap(), Xt = new WeakMap(), Je = new WeakMap(), Ni = new WeakSet(), Oa = async function(e) {
  const t = e.length;
  for (; a(this, Je) < t; ) {
    const n = new ye();
    c(this, Xt, n), await n.promise;
  }
  a(this, Je) === 1 / 0 ? c(this, Je, -1) : c(this, Je, a(this, Je) - t), await a(this, Rt).sendPacket(oe.Write, this.localId, this.remoteId, e);
};
var ge;
class dl {
  constructor(e) {
    u(this, ge);
    c(this, ge, e);
  }
  get localId() {
    return a(this, ge).localId;
  }
  get remoteId() {
    return a(this, ge).remoteId;
  }
  get localCreated() {
    return a(this, ge).localCreated;
  }
  get service() {
    return a(this, ge).service;
  }
  get readable() {
    return a(this, ge).readable;
  }
  get writable() {
    return a(this, ge).writable;
  }
  get closed() {
    return a(this, ge).closed;
  }
  close() {
    return a(this, ge).close();
  }
}
ge = new WeakMap();
var ot, Re, Ct, Pn, pr, It, gn, ce, Ma, Va, ws, ja, qa, vs;
class fl {
  constructor(e, t) {
    u(this, ce);
    // ADB socket id starts from 1
    // (0 means open failed)
    u(this, ot, new Eo(1));
    /**
     * Socket local ID to the socket controller.
     */
    u(this, Re, /* @__PURE__ */ new Map());
    u(this, Ct);
    E(this, "options");
    u(this, Pn, !1);
    u(this, pr, new ye());
    u(this, It, /* @__PURE__ */ new Map());
    u(this, gn, new pi());
    this.options = t, this.options.initialDelayedAckBytes < 0 && (this.options.initialDelayedAckBytes = 0), e.readable.pipeTo(new ze({
      write: async (n) => {
        switch (n.command) {
          case oe.Close:
            await L(this, ce, Ma).call(this, n);
            break;
          case oe.Okay:
            L(this, ce, Va).call(this, n);
            break;
          case oe.Open:
            await L(this, ce, ja).call(this, n);
            break;
          case oe.Write:
            await L(this, ce, qa).call(this, n);
            break;
          default:
            throw new Error(`Unknown command: ${n.command.toString(16)}`);
        }
      }
    }), {
      preventCancel: t.preserveConnection ?? !1,
      signal: a(this, gn).signal
    }).then(() => {
      L(this, ce, vs).call(this);
    }, (n) => {
      a(this, Pn) || a(this, pr).reject(n), L(this, ce, vs).call(this);
    }), c(this, Ct, e.writable.getWriter());
  }
  get disconnected() {
    return a(this, pr).promise;
  }
  async createSocket(e) {
    this.options.appendNullToServiceString && (e += "\0");
    const [t, n] = a(this, ot).add();
    await this.sendPacket(oe.Open, t, this.options.initialDelayedAckBytes, e);
    const { remoteId: i, availableWriteBytes: s } = await n, o = new ea({
      dispatcher: this,
      localId: t,
      remoteId: i,
      localCreated: !0,
      service: e,
      availableWriteBytes: s
    });
    return a(this, Re).set(t, o), o.socket;
  }
  addReverseTunnel(e, t) {
    a(this, It).set(e, t);
  }
  removeReverseTunnel(e) {
    a(this, It).delete(e);
  }
  clearReverseTunnels() {
    a(this, It).clear();
  }
  async sendPacket(e, t, n, i) {
    if (typeof i == "string" && (i = /* @__PURE__ */ _t(i)), i.length > this.options.maxPayloadSize)
      throw new TypeError("payload too large");
    await ue.WritableStream.write(a(this, Ct), {
      command: e,
      arg0: t,
      arg1: n,
      payload: i,
      checksum: this.options.calculateChecksum ? Na(i) : 0,
      magic: e ^ 4294967295
    });
  }
  async close() {
    await Promise.all(Array.from(a(this, Re).values(), (e) => e.close())), c(this, Pn, !0), a(this, gn).abort(), this.options.preserveConnection ? a(this, Ct).releaseLock() : await a(this, Ct).close();
  }
}
ot = new WeakMap(), Re = new WeakMap(), Ct = new WeakMap(), Pn = new WeakMap(), pr = new WeakMap(), It = new WeakMap(), gn = new WeakMap(), ce = new WeakSet(), Ma = async function(e) {
  if (e.arg0 === 0 && a(this, ot).reject(e.arg1, new Error("Socket open failed")))
    return;
  const t = a(this, Re).get(e.arg1);
  if (t) {
    await t.close(), t.dispose(), a(this, Re).delete(e.arg1);
    return;
  }
}, Va = function(e) {
  let t;
  if (this.options.initialDelayedAckBytes !== 0) {
    if (e.payload.length !== 4)
      throw new Error("Invalid OKAY packet. Payload size should be 4");
    t = fi(e.payload, 0);
  } else {
    if (e.payload.length !== 0)
      throw new Error("Invalid OKAY packet. Payload size should be 0");
    t = 1 / 0;
  }
  if (a(this, ot).resolve(e.arg1, {
    remoteId: e.arg0,
    availableWriteBytes: t
  }))
    return;
  const n = a(this, Re).get(e.arg1);
  if (n) {
    n.ack(t);
    return;
  }
  this.sendPacket(oe.Close, e.arg1, e.arg0, pe);
}, ws = function(e, t, n) {
  let i;
  return this.options.initialDelayedAckBytes !== 0 ? (i = new Uint8Array(4), Io(i, 0, n)) : i = pe, this.sendPacket(oe.Okay, e, t, i);
}, ja = async function(e) {
  const [t] = a(this, ot).add();
  a(this, ot).resolve(t, void 0);
  const n = e.arg0;
  let i = e.arg1, s = /* @__PURE__ */ Rr(e.payload);
  if (s.endsWith("\0") && (s = s.substring(0, s.length - 1)), this.options.initialDelayedAckBytes === 0) {
    if (i !== 0)
      throw new Error("Invalid OPEN packet. arg1 should be 0");
    i = 1 / 0;
  } else if (i === 0)
    throw new Error("Invalid OPEN packet. arg1 should be greater than 0");
  const o = a(this, It).get(s);
  if (!o) {
    await this.sendPacket(oe.Close, 0, n, pe);
    return;
  }
  const l = new ea({
    dispatcher: this,
    localId: t,
    remoteId: n,
    localCreated: !1,
    service: s,
    availableWriteBytes: i
  });
  try {
    await o(l.socket), a(this, Re).set(t, l), await L(this, ce, ws).call(this, t, n, this.options.initialDelayedAckBytes);
  } catch {
    await this.sendPacket(oe.Close, 0, n, pe);
  }
}, qa = async function(e) {
  const t = a(this, Re).get(e.arg1);
  if (!t)
    throw new Error(`Unknown local socket id: ${e.arg1}`);
  let n = !1;
  const i = [
    (async () => {
      await t.enqueue(e.payload), await L(this, ce, ws).call(this, e.arg1, e.arg0, e.payload.length), n = !0;
    })()
  ];
  this.options.readTimeLimit && i.push((async () => {
    if (await ha(this.options.readTimeLimit), !n)
      throw new Error(`readable of \`${t.service}\` has stalled for ${this.options.readTimeLimit} milliseconds`);
  })()), await Promise.race(i);
}, vs = function() {
  for (const e of a(this, Re).values())
    e.dispose();
  a(this, pr).resolve();
};
const hl = 16777217, ta = [
  Q.ShellV2,
  Q.Cmd,
  Q.StatV2,
  Q.ListV2,
  Q.FixedPushMkdir,
  "apex",
  Q.Abb,
  // only tells the client the symlink timestamp issue in `adb push --sync` has been fixed.
  // No special handling required.
  "fixed_push_symlink_timestamp",
  Q.AbbExec,
  "remount_shell",
  "track_app",
  Q.SendReceiveV2,
  "sendrecv_v2_brotli",
  "sendrecv_v2_lz4",
  "sendrecv_v2_zstd",
  "sendrecv_v2_dry_run_send",
  Q.DelayedAck
], pl = 32 * 1024 * 1024;
var Tn, Xe, En, Sn, mr, zn;
const Os = class Os {
  constructor({ serial: e, connection: t, version: n, banner: i, features: s = ta, initialDelayedAckBytes: o, ...l }) {
    u(this, Tn);
    u(this, Xe);
    u(this, En);
    u(this, Sn);
    u(this, mr);
    u(this, zn);
    if (c(this, En, e), c(this, Tn, t), c(this, mr, ps.parse(i)), c(this, zn, s), s.includes(Q.DelayedAck)) {
      if (o <= 0)
        throw new TypeError("`initialDelayedAckBytes` must be greater than 0 when DelayedAck feature is enabled.");
      a(this, mr).features.includes(Q.DelayedAck) || (o = 0);
    } else
      o = 0;
    let d, f;
    n >= hl ? (d = !1, f = !1) : (d = !0, f = !0), c(this, Xe, new fl(t, {
      calculateChecksum: d,
      appendNullToServiceString: f,
      initialDelayedAckBytes: o,
      ...l
    })), c(this, Sn, n);
  }
  /**
   * Authenticate with the ADB Daemon and create a new transport.
   */
  static async authenticate({ serial: e, connection: t, credentialStore: n, authenticators: i = ll, features: s = ta, initialDelayedAckBytes: o = pl, ...l }) {
    let d = 16777217, f = 1024 * 1024;
    const p = new ye(), m = new ul(i, n), b = new pi(), h = t.readable.pipeTo(new ze({
      async write(z) {
        switch (z.command) {
          case oe.Connect:
            d = Math.min(d, z.arg0), f = Math.min(f, z.arg1), p.resolve(/* @__PURE__ */ Rr(z.payload));
            break;
          case oe.Auth: {
            const C = await m.process(z);
            await v(C);
            break;
          }
        }
      }
    }), {
      // Don't cancel the source ReadableStream on AbortSignal abort.
      preventCancel: !0,
      signal: b.signal
    }).then(() => {
      p.reject(new Error("Connection closed unexpectedly"));
    }, (z) => {
      p.reject(z);
    }), y = t.writable.getWriter();
    async function v(z) {
      z.checksum = Na(z.payload), z.magic = z.command ^ 4294967295, await ue.WritableStream.write(y, z);
    }
    const T = s.slice();
    if (o <= 0) {
      const z = s.indexOf(Q.DelayedAck);
      z !== -1 && T.splice(z, 1);
    }
    let S;
    try {
      await v({
        command: oe.Connect,
        arg0: d,
        arg1: f,
        // The terminating `;` is required in formal definition
        // But ADB daemon (all versions) can still work without it
        payload: /* @__PURE__ */ _t(`host::features=${T.join(",")}`)
      }), S = await p.promise;
    } finally {
      b.abort(), y.releaseLock(), await h;
    }
    return new Os({
      serial: e,
      connection: t,
      version: d,
      maxPayloadSize: f,
      banner: S,
      features: T,
      initialDelayedAckBytes: o,
      ...l
    });
  }
  get connection() {
    return a(this, Tn);
  }
  get serial() {
    return a(this, En);
  }
  get protocolVersion() {
    return a(this, Sn);
  }
  get maxPayloadSize() {
    return a(this, Xe).options.maxPayloadSize;
  }
  get banner() {
    return a(this, mr);
  }
  get disconnected() {
    return a(this, Xe).disconnected;
  }
  get clientFeatures() {
    return a(this, zn);
  }
  connect(e) {
    return a(this, Xe).createSocket(e);
  }
  addReverseTunnel(e, t) {
    return t || (t = `localabstract:reverse_${Math.random().toString().substring(2)}`), a(this, Xe).addReverseTunnel(t, e), t;
  }
  removeReverseTunnel(e) {
    a(this, Xe).removeReverseTunnel(e);
  }
  clearReverseTunnels() {
    a(this, Xe).clearReverseTunnels();
  }
  close() {
    return a(this, Xe).close();
  }
};
Tn = new WeakMap(), Xe = new WeakMap(), En = new WeakMap(), Sn = new WeakMap(), mr = new WeakMap(), zn = new WeakMap();
let xs = Os;
function Ua() {
  return new Promise((r, e) => {
    const t = indexedDB.open("Tango", 1);
    t.onerror = () => {
      e(t.error);
    }, t.onupgradeneeded = () => {
      t.result.createObjectStore("Authentication", { autoIncrement: !0 });
    }, t.onsuccess = () => {
      const n = t.result;
      r(n);
    };
  });
}
async function ml(r) {
  const e = await Ua();
  return new Promise((t, n) => {
    const i = e.transaction("Authentication", "readwrite"), o = i.objectStore("Authentication").add(r);
    o.onerror = () => {
      n(o.error);
    }, o.onsuccess = () => {
      t();
    }, i.onerror = () => {
      n(i.error);
    }, i.oncomplete = () => {
      e.close();
    };
  });
}
async function yl() {
  const r = await Ua();
  return new Promise((e, t) => {
    const n = r.transaction("Authentication", "readonly"), s = n.objectStore("Authentication").getAll();
    s.onerror = () => {
      t(s.error);
    }, s.onsuccess = () => {
      e(s.result);
    }, n.onerror = () => {
      t(n.error);
    }, n.oncomplete = () => {
      r.close();
    };
  });
}
var yr;
class bl {
  constructor(e = "Tango") {
    u(this, yr);
    c(this, yr, e);
  }
  /**
   * Generates a RSA private key and store it into LocalStorage.
   *
   * Calling this method multiple times will overwrite the previous key.
   *
   * @returns The private key in PKCS #8 format.
   */
  async generateKey() {
    const { privateKey: e } = await crypto.subtle.generateKey({
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      // 65537
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-1"
    }, !0, ["sign", "verify"]), t = new Uint8Array(await crypto.subtle.exportKey("pkcs8", e));
    return await ml(t), {
      buffer: t,
      name: `${a(this, yr)}@${globalThis.location.hostname}`
    };
  }
  /**
   * Yields the stored RSA private key.
   *
   * This method returns a generator, so `for await...of...` loop should be used to read the key.
   */
  async *iterateKeys() {
    for (const e of await yl())
      yield {
        buffer: e,
        name: `${a(this, yr)}@${globalThis.location.hostname}`
      };
  }
}
yr = new WeakMap();
function Cs(r, e) {
  return typeof r == "object" && r !== null && "name" in r && r.name === e;
}
function wl(r) {
  return r.classCode !== void 0 && r.subclassCode !== void 0 && r.protocolCode !== void 0;
}
function vl(r, e) {
  return r.interfaceClass === e.classCode && r.interfaceSubclass === e.subclassCode && r.interfaceProtocol === e.protocolCode;
}
function xl(r, e) {
  for (const t of r.configurations)
    for (const n of t.interfaces)
      for (const i of n.alternates)
        if (vl(i, e))
          return { configuration: t, interface_: n, alternate: i };
}
function ra(r) {
  return r.toString(16).padStart(4, "0");
}
function Ba(r) {
  return r.serialNumber ? r.serialNumber : ra(r.vendorId) + "x" + ra(r.productId);
}
function Pl(r) {
  if (r.length === 0)
    throw new TypeError("No endpoints given");
  let e, t;
  for (const n of r)
    switch (n.direction) {
      case "in":
        if (e = n, t)
          return { inEndpoint: e, outEndpoint: t };
        break;
      case "out":
        if (t = n, e)
          return { inEndpoint: e, outEndpoint: t };
        break;
    }
  throw e ? t ? new Error("unreachable") : new TypeError("No output endpoint found.") : new TypeError("No input endpoint found.");
}
function gl(r, e) {
  return e.vendorId !== void 0 && r.vendorId !== e.vendorId || e.productId !== void 0 && r.productId !== e.productId || e.serialNumber !== void 0 && Ba(r) !== e.serialNumber ? !1 : wl(e) ? xl(r, e) || !1 : !0;
}
function Ai(r, e, t) {
  if (t && t.length > 0 && Ai(r, t))
    return !1;
  for (const n of e) {
    const i = gl(r, n);
    if (i)
      return i;
  }
  return !1;
}
const wi = {
  classCode: 255,
  subclassCode: 66,
  protocolCode: 1
};
function Ps(r) {
  return !r || r.length === 0 ? [wi] : r.map((e) => ({
    ...e,
    classCode: e.classCode ?? wi.classCode,
    subclassCode: e.subclassCode ?? wi.subclassCode,
    protocolCode: e.protocolCode ?? wi.protocolCode
  }));
}
var An, ct;
class Tl {
  constructor(e) {
    u(this, An);
    u(this, ct);
    c(this, An, e), c(this, ct, 0);
  }
  get position() {
    return a(this, ct);
  }
  readExactly(e) {
    const t = a(this, An).subarray(a(this, ct), a(this, ct) + e);
    return c(this, ct, a(this, ct) + e), t;
  }
}
An = new WeakMap(), ct = new WeakMap();
var Dt, lt, Ln, Rn, Xn, ki, Wa;
class El {
  constructor(e, t, n, i) {
    u(this, ki);
    u(this, Dt);
    u(this, lt);
    u(this, Ln);
    u(this, Rn);
    u(this, Xn);
    c(this, Dt, e), c(this, lt, t), c(this, Ln, n);
    let s = !1;
    const o = new $o({
      close: async () => {
        try {
          s = !0, await e.raw.close();
        } catch {
        }
      },
      dispose: () => {
        s = !0, i.removeEventListener("disconnect", l);
      }
    });
    function l(f) {
      f.device === e.raw && o.dispose().catch(bc);
    }
    i.addEventListener("disconnect", l), c(this, Rn, o.wrapReadable(new yt({
      pull: async (f) => {
        const p = await L(this, ki, Wa).call(this);
        p ? f.enqueue(p) : f.close();
      }
    }, { highWaterMark: 0 })));
    const d = n.packetSize - 1;
    c(this, Xn, rc(o.createWritable(new Bi({
      write: async (f) => {
        try {
          await e.raw.transferOut(n.endpointNumber, f), d && !(f.length & d) && await e.raw.transferOut(n.endpointNumber, pe);
        } catch (p) {
          if (s)
            return;
          throw p;
        }
      }
    })), new al()));
  }
  get device() {
    return a(this, Dt);
  }
  get inEndpoint() {
    return a(this, lt);
  }
  get outEndpoint() {
    return a(this, Ln);
  }
  get readable() {
    return a(this, Rn);
  }
  get writable() {
    return a(this, Xn);
  }
}
Dt = new WeakMap(), lt = new WeakMap(), Ln = new WeakMap(), Rn = new WeakMap(), Xn = new WeakMap(), ki = new WeakSet(), Wa = async function() {
  try {
    for (; ; ) {
      const e = await a(this, Dt).raw.transferIn(a(this, lt).endpointNumber, a(this, lt).packetSize);
      if (e.data.byteLength !== 24)
        continue;
      const t = new Uint8Array(e.data.buffer), n = new Tl(t), i = bs.deserialize(n);
      if (i.magic === (i.command ^ 4294967295)) {
        if (i.payloadLength !== 0) {
          const s = await a(this, Dt).raw.transferIn(a(this, lt).endpointNumber, i.payloadLength);
          i.payload = new Uint8Array(s.data.buffer);
        } else
          i.payload = pe;
        return i;
      }
    }
  } catch (e) {
    if (Cs(e, "NetworkError") && (await new Promise((t) => {
      setTimeout(() => {
        t();
      }, 100);
    }), closed))
      return;
    throw e;
  }
};
var Cn, In, Te, Dn, Oi, Fa;
const Ms = class Ms {
  /**
   * Create a new instance of `AdbDaemonWebUsbConnection` using a specified `USBDevice` instance
   *
   * @param device The `USBDevice` instance obtained elsewhere.
   * @param filters The filters to use when searching for ADB interface. Defaults to {@link ADB_DEFAULT_DEVICE_FILTER}.
   */
  constructor(e, t, n) {
    u(this, Oi);
    u(this, Cn);
    u(this, In);
    u(this, Te);
    u(this, Dn);
    c(this, Te, e), c(this, Dn, Ba(e)), c(this, Cn, t), c(this, In, n);
  }
  get raw() {
    return a(this, Te);
  }
  get serial() {
    return a(this, Dn);
  }
  get name() {
    return a(this, Te).productName;
  }
  /**
   * Open the device and create a new connection to the ADB Daemon.
   */
  async connect() {
    const { inEndpoint: e, outEndpoint: t } = await L(this, Oi, Fa).call(this);
    return new El(this, e, t, a(this, In));
  }
};
Cn = new WeakMap(), In = new WeakMap(), Te = new WeakMap(), Dn = new WeakMap(), Oi = new WeakSet(), Fa = async function() {
  var i;
  a(this, Te).opened || await a(this, Te).open();
  const { configuration: e, interface_: t, alternate: n } = a(this, Cn);
  if (((i = a(this, Te).configuration) == null ? void 0 : i.configurationValue) !== e.configurationValue && await a(this, Te).selectConfiguration(e.configurationValue), !t.claimed)
    try {
      await a(this, Te).claimInterface(t.interfaceNumber);
    } catch (s) {
      throw Cs(s, "NetworkError") ? new Ms.DeviceBusyError(s) : s;
    }
  return t.alternate.alternateSetting !== n.alternateSetting && await a(this, Te).selectAlternateInterface(t.interfaceNumber, n.alternateSetting), Pl(n.endpoints);
};
let Kt = Ms;
(function(r) {
  class e extends Error {
    constructor(n) {
      super("The device is already in used by another program", {
        cause: n
      });
    }
  }
  r.DeviceBusyError = e;
})(Kt || (Kt = {}));
var Hn, Nn, Ke, br, wr, Ht, kn, On;
class Sl {
  constructor(e, t = {}) {
    u(this, Hn);
    u(this, Nn);
    u(this, Ke);
    u(this, br, new vi());
    E(this, "onDeviceAdd", a(this, br).event);
    u(this, wr, new vi());
    E(this, "onDeviceRemove", a(this, wr).event);
    u(this, Ht, new vi());
    E(this, "onListChange", a(this, Ht).event);
    E(this, "current", []);
    u(this, kn, (e) => {
      const t = Ai(e.device, a(this, Hn), a(this, Nn));
      if (!t)
        return;
      const n = new Kt(e.device, t, a(this, Ke));
      a(this, br).fire([n]), this.current.push(n), a(this, Ht).fire(this.current);
    });
    u(this, On, (e) => {
      const t = this.current.findIndex((n) => n.raw === e.device);
      if (t !== -1) {
        const n = this.current[t];
        a(this, wr).fire([n]), this.current[t] = this.current[this.current.length - 1], this.current.length -= 1, a(this, Ht).fire(this.current);
      }
    });
    c(this, Hn, Ps(t.filters)), c(this, Nn, t.exclusionFilters), c(this, Ke, e), a(this, Ke).addEventListener("connect", a(this, kn)), a(this, Ke).addEventListener("disconnect", a(this, On));
  }
  stop() {
    a(this, Ke).removeEventListener("connect", a(this, kn)), a(this, Ke).removeEventListener("disconnect", a(this, On)), a(this, br).dispose(), a(this, wr).dispose(), a(this, Ht).dispose();
  }
}
Hn = new WeakMap(), Nn = new WeakMap(), Ke = new WeakMap(), br = new WeakMap(), wr = new WeakMap(), Ht = new WeakMap(), kn = new WeakMap(), On = new WeakMap();
var Qe;
const Mi = class Mi {
  /**
   * Create a new instance of {@link AdbDaemonWebUsbDeviceManager} using the specified WebUSB implementation.
   * @param usbManager A WebUSB compatible interface.
   */
  constructor(e) {
    u(this, Qe);
    c(this, Qe, e);
  }
  /**
   * Call `USB#requestDevice()` to prompt the user to select a device.
   */
  async requestDevice(e = {}) {
    const t = Ps(e.filters);
    try {
      const n = await a(this, Qe).requestDevice({
        filters: t,
        exclusionFilters: e.exclusionFilters
      }), i = Ai(n, t, e.exclusionFilters);
      return i ? new Kt(n, i, a(this, Qe)) : void 0;
    } catch (n) {
      if (Cs(n, "NotFoundError"))
        return;
      throw n;
    }
  }
  /**
   * Get all connected and requested devices that match the specified filters.
   */
  async getDevices(e = {}) {
    const t = Ps(e.filters), n = await a(this, Qe).getDevices(), i = [];
    for (const s of n) {
      const o = Ai(s, t, e.exclusionFilters);
      o && i.push(new Kt(s, o, a(this, Qe)));
    }
    return i;
  }
  trackDevices(e = {}) {
    return new Sl(a(this, Qe), e);
  }
};
Qe = new WeakMap(), /**
 * Gets the instance of {@link AdbDaemonWebUsbDeviceManager} using browser WebUSB implementation.
 *
 * May be `undefined` if current runtime does not support WebUSB.
 */
E(Mi, "BROWSER", typeof globalThis.navigator < "u" && globalThis.navigator.usb ? new Mi(globalThis.navigator.usb) : void 0);
let Or = Mi;
const $t = /* @__PURE__ */ M({ type: Y }, { littleEndian: !1 }), Ne = class Ne {
  constructor(e, t, n, i) {
    E(this, "optionValue");
    E(this, "metadataValue");
    E(this, "mimeType");
    E(this, "webCodecId");
    this.optionValue = e, this.metadataValue = t, this.mimeType = n, this.webCodecId = i;
  }
  toOptionValue() {
    return this.optionValue;
  }
};
E(Ne, "Opus", /* @__PURE__ */ new Ne("opus", 1869641075, "audio/opus", "opus")), E(Ne, "Aac", /* @__PURE__ */ new Ne("aac", 6381923, "audio/aac", "mp4a.66")), E(Ne, "Flac", /* @__PURE__ */ new Ne("flac", 1718378851, "audio/flac", "flac")), E(Ne, "Raw", /* @__PURE__ */ new Ne("raw", 7496055, "audio/raw", ""));
let de = Ne;
const O = {
  InjectKeyCode: 0,
  InjectText: 1,
  InjectTouch: 2,
  InjectScroll: 3,
  BackOrScreenOn: 4,
  ExpandNotificationPanel: 5,
  ExpandSettingPanel: 6,
  CollapseNotificationPanel: 7,
  GetClipboard: 8,
  SetClipboard: 9,
  SetDisplayPower: 10,
  RotateDevice: 11,
  UHidCreate: 12,
  UHidInput: 13,
  UHidDestroy: 14,
  OpenHardKeyboardSettings: 15,
  StartApp: 16,
  ResetVideo: 17
};
function zl(r) {
  return typeof r == "object" && r !== null && "toOptionValue" in r && typeof r.toOptionValue == "function";
}
function Li(r, e) {
  if (zl(r) && (r = r.toOptionValue()), r === void 0)
    return e;
  if (typeof r != "string" && typeof r != "number" && typeof r != "boolean")
    throw new TypeError(`Invalid option value: ${JSON.stringify(r)}`);
  return r.toString();
}
const nt = {
  H264: 1748121140,
  H265: 1748121141,
  AV1: 6387249
}, Al = /* @__PURE__ */ M({
  type: Y(O.InjectKeyCode),
  action: Y(),
  keyCode: g(),
  repeat: g,
  metaState: g()
}, { littleEndian: !1 }), Ll = /* @__PURE__ */ M({ type: Y, text: qe(g) }, { littleEndian: !1 });
var Mn;
class Rl {
  constructor(e) {
    u(this, Mn);
    c(this, Mn, e.controlMessageTypes);
  }
  get(e) {
    const t = a(this, Mn).indexOf(e);
    if (t === -1)
      throw new TypeError("Invalid or unsupported control message type");
    return t;
  }
  fillMessageType(e, t) {
    return e.type = this.get(t), e;
  }
}
Mn = new WeakMap();
const Xl = /* @__PURE__ */ M({ type: Y, mode: Y() }, { littleEndian: !1 }), Cl = /* @__PURE__ */ M({
  type: Y,
  name: qe(Y)
}, { littleEndian: !1 }), Il = /* @__PURE__ */ M({
  type: Y(O.UHidInput),
  id: xe,
  data: it(xe)
}, { littleEndian: !1 }), Dl = /* @__PURE__ */ M({ type: Y, id: xe }, { littleEndian: !1 });
var _e, B, Vn;
class Hl {
  constructor(e) {
    u(this, _e);
    u(this, B);
    u(this, Vn);
    c(this, _e, e), c(this, B, new Rl(e)), c(this, Vn, e.createScrollController());
  }
  injectKeyCode(e) {
    return Al.serialize(a(this, B).fillMessageType(e, O.InjectKeyCode));
  }
  injectText(e) {
    return Ll.serialize({
      text: e,
      type: a(this, B).get(O.InjectText)
    });
  }
  /**
   * `pressure` is a float value between 0 and 1.
   */
  injectTouch(e) {
    return a(this, _e).serializeInjectTouchControlMessage(a(this, B).fillMessageType(e, O.InjectTouch));
  }
  /**
   * `scrollX` and `scrollY` are float values between 0 and 1.
   */
  injectScroll(e) {
    return a(this, Vn).serializeScrollMessage(a(this, B).fillMessageType(e, O.InjectScroll));
  }
  backOrScreenOn(e) {
    return a(this, _e).serializeBackOrScreenOnControlMessage({
      action: e,
      type: a(this, B).get(O.BackOrScreenOn)
    });
  }
  setDisplayPower(e) {
    return Xl.serialize({
      mode: e,
      type: a(this, B).get(O.SetDisplayPower)
    });
  }
  expandNotificationPanel() {
    return $t.serialize({
      type: a(this, B).get(O.ExpandNotificationPanel)
    });
  }
  expandSettingPanel() {
    return $t.serialize({
      type: a(this, B).get(O.ExpandSettingPanel)
    });
  }
  collapseNotificationPanel() {
    return $t.serialize({
      type: a(this, B).get(O.CollapseNotificationPanel)
    });
  }
  rotateDevice() {
    return $t.serialize({
      type: a(this, B).get(O.RotateDevice)
    });
  }
  setClipboard(e) {
    return a(this, _e).serializeSetClipboardControlMessage({
      ...e,
      type: a(this, B).get(O.SetClipboard)
    });
  }
  uHidCreate(e) {
    if (!a(this, _e).serializeUHidCreateControlMessage)
      throw new Error("UHid not supported");
    return a(this, _e).serializeUHidCreateControlMessage(a(this, B).fillMessageType(e, O.UHidCreate));
  }
  uHidInput(e) {
    return Il.serialize(a(this, B).fillMessageType(e, O.UHidInput));
  }
  uHidDestroy(e) {
    return Dl.serialize({
      type: a(this, B).get(O.UHidDestroy),
      id: e
    });
  }
  startApp(e, t) {
    return t != null && t.searchByName && (e = "?" + e), t != null && t.forceStop && (e = "+" + e), Cl.serialize({
      type: a(this, B).get(O.StartApp),
      name: e
    });
  }
  resetVideo() {
    return $t.serialize({
      type: a(this, B).get(O.ResetVideo)
    });
  }
}
_e = new WeakMap(), B = new WeakMap(), Vn = new WeakMap();
var Nt, W;
class Nl {
  constructor(e, t) {
    u(this, Nt);
    u(this, W);
    c(this, Nt, e), c(this, W, new Hl(t));
  }
  write(e) {
    return ue.WritableStream.write(a(this, Nt), e);
  }
  injectKeyCode(e) {
    return this.write(a(this, W).injectKeyCode(e));
  }
  injectText(e) {
    return this.write(a(this, W).injectText(e));
  }
  /**
   * `pressure` is a float value between 0 and 1.
   */
  injectTouch(e) {
    return this.write(a(this, W).injectTouch(e));
  }
  /**
   * `scrollX` and `scrollY` are float values between 0 and 1.
   */
  async injectScroll(e) {
    const t = a(this, W).injectScroll(e);
    t && await this.write(t);
  }
  async backOrScreenOn(e) {
    const t = a(this, W).backOrScreenOn(e);
    t && await this.write(t);
  }
  setScreenPowerMode(e) {
    return this.write(a(this, W).setDisplayPower(e));
  }
  expandNotificationPanel() {
    return this.write(a(this, W).expandNotificationPanel());
  }
  expandSettingPanel() {
    return this.write(a(this, W).expandSettingPanel());
  }
  collapseNotificationPanel() {
    return this.write(a(this, W).collapseNotificationPanel());
  }
  rotateDevice() {
    return this.write(a(this, W).rotateDevice());
  }
  async setClipboard(e) {
    const t = a(this, W).setClipboard(e);
    t instanceof Uint8Array ? await this.write(t) : (await this.write(t[0]), await t[1]);
  }
  uHidCreate(e) {
    return this.write(a(this, W).uHidCreate(e));
  }
  uHidInput(e) {
    return this.write(a(this, W).uHidInput(e));
  }
  uHidDestroy(e) {
    return this.write(a(this, W).uHidDestroy(e));
  }
  startApp(e, t) {
    return this.write(a(this, W).startApp(e, t));
  }
  resetVideo() {
    return this.write(a(this, W).resetVideo());
  }
  releaseLock() {
    a(this, Nt).releaseLock();
  }
  async close() {
    await a(this, Nt).close();
  }
}
Nt = new WeakMap(), W = new WeakMap();
const kl = $t, Ol = /* @__PURE__ */ M({ content: qe(g) }, { littleEndian: !1 });
var kt;
class Ml extends Se {
  constructor() {
    let t;
    super((n) => {
      t = n;
    });
    u(this, kt);
    c(this, kt, t);
  }
  async parse(t, n) {
    if (t === 0) {
      const i = await Ol.deserialize(n);
      return await a(this, kt).enqueue(i.content), !0;
    }
    return !1;
  }
  close() {
    a(this, kt).close();
  }
  error(t) {
    a(this, kt).error(t);
  }
}
kt = new WeakMap();
const Vl = [
  /*  0 */
  O.InjectKeyCode,
  /*  1 */
  O.InjectText,
  /*  2 */
  O.InjectTouch,
  /*  3 */
  O.InjectScroll,
  /*  4 */
  O.BackOrScreenOn,
  /*  5 */
  O.ExpandNotificationPanel,
  /*  6 */
  O.CollapseNotificationPanel,
  /*  7 */
  O.GetClipboard,
  /*  8 */
  O.SetClipboard,
  /*  9 */
  O.SetDisplayPower,
  /* 10 */
  O.RotateDevice
], jl = {
  Unlocked: -1
}, ql = {
  logLevel: "debug",
  maxSize: 0,
  bitRate: 8e6,
  maxFps: 0,
  lockVideoOrientation: jl.Unlocked,
  tunnelForward: !1,
  crop: void 0,
  sendFrameMeta: !0,
  control: !0,
  displayId: 0,
  showTouches: !1,
  stayAwake: !1,
  codecOptions: void 0
};
function Za(r, e, t) {
  return r < e ? e : r > t ? t : r;
}
const Ul = "/data/local/tmp/scrcpy-server.jar";
// @__NO_SIDE_EFFECTS__
function Ga(r, ...e) {
  return Object.fromEntries(Object.entries(r).filter(([t]) => !e.includes(t)));
}
var j;
class Bl {
  constructor(e) {
    u(this, j);
    c(this, j, e);
  }
  get version() {
    return a(this, j).version;
  }
  get controlMessageTypes() {
    return a(this, j).controlMessageTypes;
  }
  get value() {
    return a(this, j).value;
  }
  get clipboard() {
    return a(this, j).clipboard;
  }
  get uHidOutput() {
    return a(this, j).uHidOutput;
  }
  serialize() {
    return a(this, j).serialize();
  }
  setListDisplays() {
    a(this, j).setListDisplays();
  }
  parseDisplay(e) {
    return a(this, j).parseDisplay(e);
  }
  setListEncoders() {
    if (!a(this, j).setListEncoders)
      throw new Error("setListEncoders is not implemented");
    a(this, j).setListEncoders();
  }
  parseEncoder(e) {
    if (!a(this, j).parseEncoder)
      throw new Error("parseEncoder is not implemented");
    return a(this, j).parseEncoder(e);
  }
  parseVideoStreamMetadata(e) {
    return a(this, j).parseVideoStreamMetadata(e);
  }
  parseAudioStreamMetadata(e) {
    if (!a(this, j).parseAudioStreamMetadata)
      throw new Error("parseAudioStreamMetadata is not implemented");
    return a(this, j).parseAudioStreamMetadata(e);
  }
  parseDeviceMessage(e, t) {
    return a(this, j).parseDeviceMessage(e, t);
  }
  endDeviceMessageStream(e) {
    a(this, j).endDeviceMessageStream(e);
  }
  createMediaStreamTransformer() {
    return a(this, j).createMediaStreamTransformer();
  }
  serializeInjectTouchControlMessage(e) {
    return a(this, j).serializeInjectTouchControlMessage(e);
  }
  serializeBackOrScreenOnControlMessage(e) {
    return a(this, j).serializeBackOrScreenOnControlMessage(e);
  }
  serializeSetClipboardControlMessage(e) {
    return a(this, j).serializeSetClipboardControlMessage(e);
  }
  createScrollController() {
    return a(this, j).createScrollController();
  }
  serializeUHidCreateControlMessage(e) {
    if (!a(this, j).serializeUHidCreateControlMessage)
      throw new Error("serializeUHidCreateControlMessage is not implemented");
    return a(this, j).serializeUHidCreateControlMessage(e);
  }
}
j = new WeakMap();
const Wl = {
  size: 2,
  serialize(r, { buffer: e, index: t, littleEndian: n }) {
    r = Za(r, -1, 1), r = r === 1 ? 65535 : r * 65536, ma(e, t, r, n);
  },
  deserialize: me(function* (r, { reader: e, littleEndian: t }) {
    const n = yield* r(e.readExactly(2)), i = pa(n, 0, t);
    return i === 65535 ? 1 : i / 65536;
  })
}, Fl = /* @__PURE__ */ M({ pts: je, data: it(g) }, { littleEndian: !1 }), Zl = 1n << 63n;
async function Gl(r, e) {
  const t = await r.readExactly(e);
  return /* @__PURE__ */ Rr(t.subarray(0, t.indexOf(0)));
}
async function ts(r) {
  const e = await r.readExactly(4);
  return ya(e, 0);
}
const Yl = {
  ...ql,
  encoderName: void 0
}, Jl = /* @__PURE__ */ M({
  ...kl.fields,
  action: Y()
}, { littleEndian: !1 });
function Kl(r) {
  return Jl.serialize(r);
}
const Ql = /* @__PURE__ */ (() => {
  const r = Vl.slice();
  return r.splice(6, 0, O.ExpandSettingPanel), r;
})(), _l = {
  Unlocked: -1
}, $l = {
  ...Yl,
  logLevel: "debug",
  lockVideoOrientation: _l.Unlocked,
  powerOffOnClose: !1
}, eu = {
  ...$l,
  clipboardAutosync: !0
};
function tu(r) {
  return r.replace(/([A-Z])/g, "_$1").toLowerCase();
}
function ru(r, e) {
  const t = [];
  for (const [n, i] of Object.entries(r)) {
    const s = Li(i, void 0);
    if (s === void 0)
      continue;
    const o = Li(e[n], void 0);
    s !== o && t.push(`${tu(n)}=${s}`);
  }
  return t;
}
const nu = /* @__PURE__ */ M({ sequence: je }, { littleEndian: !1 }), na = /* @__PURE__ */ M({
  type: Y,
  sequence: je,
  paste: Y(),
  content: qe(g)
}, { littleEndian: !1 });
var ke, vr;
class iu {
  constructor() {
    u(this, ke, /* @__PURE__ */ new Map());
    u(this, vr, !1);
  }
  async parse(e, t) {
    if (e !== 1)
      return !1;
    const n = await nu.deserialize(t), i = a(this, ke).get(n.sequence);
    return i && (i.resolve(), a(this, ke).delete(n.sequence)), !0;
  }
  close() {
    for (const e of a(this, ke).values())
      e.reject();
    a(this, ke).clear(), c(this, vr, !0);
  }
  error(e) {
    for (const t of a(this, ke).values())
      t.reject(e);
    a(this, ke).clear(), c(this, vr, !0);
  }
  serializeSetClipboardControlMessage(e) {
    if (e.sequence === 0n)
      return na.serialize(e);
    if (a(this, vr))
      throw new Error();
    const t = new ye();
    return a(this, ke).set(e.sequence, t), [
      na.serialize(e),
      t.promise
    ];
  }
}
ke = new WeakMap(), vr = new WeakMap();
const su = {
  ...eu,
  downsizeOnError: !0,
  sendDeviceMeta: !0,
  sendDummyByte: !0
}, au = {
  ...su,
  cleanup: !0
}, ia = 1n << 62n;
function ou(r) {
  if (!r.sendFrameMeta)
    return new Lr({
      transform(t, n) {
        n.enqueue({
          type: "data",
          data: t
        });
      }
    });
  const e = new Pa(Fl);
  return {
    writable: e.writable,
    readable: e.readable.pipeThrough(new Lr({
      transform(t, n) {
        if (t.pts === Zl) {
          n.enqueue({
            type: "configuration",
            data: t.data
          });
          return;
        }
        if (t.pts & ia) {
          n.enqueue({
            type: "data",
            keyframe: !0,
            pts: t.pts & ~ia,
            data: t.data
          });
          return;
        }
        n.enqueue({
          type: "data",
          keyframe: !1,
          pts: t.pts,
          data: t.data
        });
      }
    }))
  };
}
const cu = {
  ...au,
  powerOn: !0
}, sa = {
  size: 2,
  serialize(r, { buffer: e, index: t, littleEndian: n }) {
    r = Za(r, -1, 1), r = r === 1 ? 32767 : r * 32768, zo(e, t, r, n);
  },
  deserialize: me(function* (r, { reader: e, littleEndian: t }) {
    const n = yield* r(e.readExactly(2)), i = So(n, 0, t);
    return i === 32767 ? 1 : i / 32768;
  })
}, lu = /* @__PURE__ */ M({
  type: Y(O.InjectScroll),
  pointerX: g,
  pointerY: g,
  screenWidth: xe,
  screenHeight: xe,
  scrollX: sa,
  scrollY: sa,
  buttons: g
}, { littleEndian: !1 });
class uu {
  serializeScrollMessage(e) {
    return lu.serialize(e);
  }
}
function du() {
  return new uu();
}
const fu = {
  .../* @__PURE__ */ Ga(cu, "bitRate", "codecOptions", "encoderName"),
  scid: void 0,
  videoCodec: "h264",
  videoBitRate: 8e6,
  videoCodecOptions: void 0,
  videoEncoder: void 0,
  audio: !0,
  audioCodec: "opus",
  audioBitRate: 128e3,
  audioCodecOptions: void 0,
  audioEncoder: void 0,
  listEncoders: !1,
  listDisplays: !1,
  sendCodecMeta: !0
}, hu = /* @__PURE__ */ M({
  type: Y(O.InjectTouch),
  action: Y(),
  pointerId: je,
  pointerX: g,
  pointerY: g,
  screenWidth: xe,
  screenHeight: xe,
  pressure: Wl,
  actionButton: g,
  buttons: g
}, { littleEndian: !1 });
function pu(r) {
  return hu.serialize(r);
}
async function mu(r, e) {
  const t = new bt(r), n = await t.readExactly(4), i = ya(n, 0);
  switch (i) {
    case 0:
      return {
        type: "disabled"
      };
    case 1:
      return {
        type: "errored"
      };
  }
  if (e.sendCodecMeta) {
    let o;
    switch (i) {
      case de.Raw.metadataValue:
        o = de.Raw;
        break;
      case de.Opus.metadataValue:
        o = de.Opus;
        break;
      case de.Aac.metadataValue:
        o = de.Aac;
        break;
      case de.Flac.metadataValue:
        o = de.Flac;
        break;
      default:
        throw new Error(`Unknown audio codec metadata value: ${i}`);
    }
    return {
      type: "success",
      codec: o,
      stream: t.release()
    };
  }
  let s;
  switch (e.audioCodec) {
    case "raw":
      s = de.Raw;
      break;
    case "opus":
      s = de.Opus;
      break;
    case "aac":
      s = de.Aac;
      break;
    case "flac":
      s = de.Flac;
      break;
    default:
      throw new Error(`Unknown audio codec metadata value: ${i}`);
  }
  return {
    type: "success",
    codec: s,
    stream: new Se(async (o) => {
      await o.enqueue(n);
      const d = t.release().getReader();
      for (; ; ) {
        const { done: f, value: p } = await d.read();
        if (f)
          break;
        await o.enqueue(p);
      }
    })
  };
}
function Ya(r) {
  switch (r) {
    case "h264":
      return nt.H264;
    case "h265":
      return nt.H265;
    case "av1":
      return nt.AV1;
    default:
      throw new Error(`Unknown video codec: ${r}`);
  }
}
async function yu(r, e) {
  const t = new bt(e);
  let n;
  r.sendDeviceMeta && (n = await Gl(t, 64));
  let i, s, o;
  return r.sendCodecMeta ? (i = await ts(t), s = await ts(t), o = await ts(t)) : i = Ya(r.videoCodec), {
    stream: t.release(),
    metadata: { deviceName: n, codec: i, width: s, height: o }
  };
}
function bu(r, e) {
  return !r.sendDeviceMeta && !r.sendCodecMeta ? {
    stream: e,
    metadata: { codec: Ya(r.videoCodec) }
  } : yu(r, e);
}
function wu(r) {
  r.listDisplays = !0;
}
function vu(r) {
  r.listEncoders = !0;
}
const xu = {
  ...fu,
  video: !0,
  audioSource: "output"
}, Pu = {
  ...xu,
  videoSource: "display",
  displayId: 0,
  cameraId: void 0,
  cameraSize: void 0,
  cameraFacing: void 0,
  cameraAr: void 0,
  cameraFps: void 0,
  cameraHighSpeed: !1,
  listCameras: !1,
  listCameraSizes: !1
};
function gu(r) {
  const e = r.match(/^\s+--display-id=(\d+)\s+\(([^)]+)\)$/);
  if (e) {
    const t = {
      id: Number.parseInt(e[1], 10)
    };
    return e[2] !== "size unknown" && (t.resolution = e[2]), t;
  }
}
const Tu = [
  ...Ql,
  O.UHidCreate,
  O.UHidInput,
  O.OpenHardKeyboardSettings
], Eu = /* @__PURE__ */ M({
  id: xe,
  data: it(xe)
}, { littleEndian: !1 });
var Ot;
class Su extends Se {
  constructor() {
    let t;
    super((n) => {
      t = n;
    });
    u(this, Ot);
    c(this, Ot, t);
  }
  async parse(t, n) {
    if (t !== 2)
      return !1;
    const i = await Eu.deserialize(n);
    return await a(this, Ot).enqueue(i), !0;
  }
  close() {
    a(this, Ot).close();
  }
  error(t) {
    a(this, Ot).error(t);
  }
}
Ot = new WeakMap();
const zu = {
  ...Pu,
  audioDup: !1
}, Au = /* @__PURE__ */ (() => {
  const r = Tu.slice();
  return r.splice(14, 0, O.UHidDestroy), r;
})(), Lu = [
  ...Au,
  O.StartApp,
  O.ResetVideo
], Ru = {
  .../* @__PURE__ */ Ga(zu, "lockVideoOrientation"),
  captureOrientation: void 0,
  angle: 0,
  screenOffTimeout: void 0,
  listApps: !1,
  newDisplay: void 0,
  vdSystemDecorations: !0
}, Xu = /^\s+--(video|audio)-codec=(\S+)\s+--\1-encoder=(\S+)(?:\s*\((sw|hw|hybrid)\))?(?:\s*\[vendor\])?(?:\s*\(alias for (\S+)\))?$/;
function Cu(r) {
  switch (r) {
    case "sw":
      return "software";
    case "hw":
      return "hardware";
    case "hybrid":
      return "hybrid";
    default:
      throw new Error(`Unknown hardware type: ${r}`);
  }
}
function Iu(r) {
  const e = r.match(Xu);
  return e ? {
    type: e[1],
    name: e[3],
    codec: e[2],
    hardwareType: e[4] ? Cu(e[4]) : void 0,
    vendor: !!e[5],
    aliasFor: e[6]
  } : void 0;
}
const rs = {
  ...Ru,
  vdDestroyContent: !1
}, Du = /* @__PURE__ */ M({
  type: Y(O.UHidCreate),
  id: xe,
  vendorId: xe,
  productId: xe,
  name: qe(Y),
  data: it(xe)
}, { littleEndian: !1 });
function Hu(r) {
  return Du.serialize(r);
}
var ut, dt, jn;
class Ja {
  constructor(e, t = "3.1") {
    E(this, "version");
    E(this, "value");
    u(this, ut);
    u(this, dt);
    u(this, jn);
    this.value = { ...rs, ...e }, this.version = t, this.value.videoSource === "camera" && (this.value.control = !1), this.value.audioDup && (this.value.audioSource = "playback"), this.value.control && (this.value.clipboardAutosync && (c(this, ut, new Ml()), c(this, dt, new iu())), c(this, jn, new Su()));
  }
  get controlMessageTypes() {
    return Lu;
  }
  get clipboard() {
    return a(this, ut);
  }
  get uHidOutput() {
    return a(this, jn);
  }
  serialize() {
    return ru(this.value, rs);
  }
  setListDisplays() {
    wu(this.value);
  }
  parseDisplay(e) {
    return gu(e);
  }
  setListEncoders() {
    vu(this.value);
  }
  parseEncoder(e) {
    return Iu(e);
  }
  parseVideoStreamMetadata(e) {
    return bu(this.value, e);
  }
  parseAudioStreamMetadata(e) {
    return mu(e, this.value);
  }
  async parseDeviceMessage(e, t) {
    var n, i;
    if (!await ((n = a(this, ut)) == null ? void 0 : n.parse(e, t)) && !await ((i = a(this, dt)) == null ? void 0 : i.parse(e, t)))
      throw new Error("Unknown device message");
  }
  endDeviceMessageStream(e) {
    var t, n, i, s;
    e ? ((t = a(this, ut)) == null || t.error(e), (n = a(this, dt)) == null || n.error(e)) : ((i = a(this, ut)) == null || i.close(), (s = a(this, dt)) == null || s.close());
  }
  createMediaStreamTransformer() {
    return ou(this.value);
  }
  serializeInjectTouchControlMessage(e) {
    return pu(e);
  }
  serializeBackOrScreenOnControlMessage(e) {
    return Kl(e);
  }
  serializeSetClipboardControlMessage(e) {
    return a(this, dt).serializeSetClipboardControlMessage(e);
  }
  createScrollController() {
    return du();
  }
  serializeUHidCreateControlMessage(e) {
    return Hu(e);
  }
}
ut = new WeakMap(), dt = new WeakMap(), jn = new WeakMap(), E(Ja, "Defaults", rs);
var Ce, Oe, te, he;
class Nu {
  constructor(e) {
    u(this, Ce);
    u(this, Oe);
    u(this, te, 0);
    u(this, he, 7);
    c(this, Ce, e), c(this, Oe, e[0]);
  }
  get byteAligned() {
    return a(this, he) === 7;
  }
  get ended() {
    return a(this, te) >= a(this, Ce).length;
  }
  f1() {
    const e = a(this, Oe) >> a(this, he);
    return c(this, he, a(this, he) - 1), a(this, he) < 0 && (c(this, te, a(this, te) + 1), c(this, he, 7), c(this, Oe, a(this, Ce)[a(this, te)])), e & 1;
  }
  f(e) {
    let t = 0;
    for (; e > 0; e -= 1)
      t <<= 1, t |= this.f1();
    return t;
  }
  skip(e) {
    if (e <= a(this, he) + 1) {
      c(this, te, a(this, te) + 1), c(this, he, 7), c(this, Oe, a(this, Ce)[a(this, te)]);
      return;
    }
    e -= a(this, he) + 1, c(this, te, a(this, te) + 1);
    const t = e / 8 | 0;
    t > 0 && (c(this, te, a(this, te) + t), e -= t * 8), c(this, he, 7 - e), c(this, Oe, a(this, Ce)[a(this, te)]);
  }
  readBytes(e) {
    if (!this.byteAligned)
      throw new Error("Bytes must be byte-aligned");
    const t = a(this, Ce).subarray(a(this, te), a(this, te) + e);
    return c(this, te, a(this, te) + e), c(this, Oe, a(this, Ce)[a(this, te)]), t;
  }
  getPosition() {
    return [a(this, te), a(this, he)];
  }
  setPosition([e, t]) {
    c(this, te, e), c(this, he, t), c(this, Oe, a(this, Ce)[e]);
  }
}
Ce = new WeakMap(), Oe = new WeakMap(), te = new WeakMap(), he = new WeakMap();
const ku = {
  SequenceHeader: 1,
  TemporalDelimiter: 2,
  FrameHeader: 3,
  TileGroup: 4,
  Metadata: 5,
  Frame: 6,
  RedundantFrameHeader: 7,
  TileList: 8,
  Padding: 15
}, Ou = {
  Bt709: 1,
  Unspecified: 2,
  Bt470M: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  GenericFilm: 8,
  Bt2020: 9,
  Xyz: 10,
  Smpte431: 11,
  Smpte432: 12,
  Ebu3213: 22
}, Mu = {
  Bt709: 1,
  Unspecified: 2,
  Bt470M: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  Linear: 8,
  Log100: 9,
  Log100Sqrt10: 10,
  Iec61966: 11,
  Bt1361: 12,
  Srgb: 13,
  Bt2020Ten: 14,
  Bt2020Twelve: 15,
  Smpte2084: 16,
  Smpte428: 17,
  Hlg: 18
}, Vu = {
  Identity: 0,
  Bt709: 1,
  Unspecified: 2,
  Fcc: 4,
  Bt470BG: 5,
  Bt601: 6,
  Smpte240: 7,
  YCgCo: 8,
  Bt2020Ncl: 9,
  Bt2020Cl: 10,
  Smpte2085: 11,
  ChromatNcl: 12,
  ChromatCl: 13,
  ICtCp: 14
};
var Mt, Vt;
const Z = class Z extends Nu {
  constructor() {
    super(...arguments);
    u(this, Mt, 0);
    u(this, Vt, 0);
  }
  uvlc() {
    let t = 0;
    for (; !this.f1(); )
      t += 1;
    return t >= 32 ? 2 ** 32 - 1 : this.f(t) + (1 << t >>> 0) - 1;
  }
  leb128() {
    if (!this.byteAligned)
      throw new Error("LEB128 must be byte-aligned");
    let t = 0n;
    c(this, Mt, 0);
    for (let n = 0n; n < 8n; n += 1n) {
      const i = this.f(8);
      if (t |= BigInt(i & 127) << 7n * n, c(this, Mt, a(this, Mt) + 1), !(i & 128))
        break;
    }
    return t;
  }
  *annexBBitstream() {
    for (; !this.ended; ) {
      const t = this.leb128();
      yield* this.temporalUnit(t);
    }
  }
  *temporalUnit(t) {
    for (; t > 0; ) {
      const n = this.leb128();
      t -= BigInt(a(this, Mt)), yield* this.frameUnit(n), t -= n;
    }
  }
  *frameUnit(t) {
    for (; t > 0; ) {
      const n = this.leb128();
      t -= BigInt(a(this, Mt));
      const i = this.openBitstreamUnit(n);
      i && (yield i), t -= n;
    }
  }
  openBitstreamUnit(t) {
    const n = this.obuHeader();
    let i;
    if (n.obu_has_size_field)
      i = this.leb128();
    else if (t !== void 0)
      i = t - 1n - (n.obu_extension_flag ? 1n : 0n);
    else
      throw new Error("obu_has_size_field must be true");
    const s = this.getPosition();
    if (n.obu_type !== Z.ObuType.SequenceHeader && n.obu_type !== Z.ObuType.TemporalDelimiter && a(this, Vt) !== 0 && n.obu_extension_header) {
      const f = !!(a(this, Vt) & 1 << n.obu_extension_header.temporal_id), p = !!(a(this, Vt) & 1 << n.obu_extension_header.spatial_id + 8);
      if (!f || !p) {
        this.skip(Number(i));
        return;
      }
    }
    let o;
    switch (n.obu_type) {
      case Z.ObuType.SequenceHeader:
        o = this.sequenceHeaderObu();
        break;
    }
    const l = this.getPosition(), d = (l[0] - s[0]) * 8 + (s[1] - l[1]);
    return i > 0 && this.skip(Number(i) * 8 - d), {
      obu_header: n,
      obu_size: i,
      sequence_header_obu: o
    };
  }
  obuHeader() {
    if (!!this.f1())
      throw new Error("Invalid data");
    const n = this.f(4), i = !!this.f1(), s = !!this.f1();
    this.f1();
    let o;
    return i && (o = this.obuExtensionHeader()), {
      obu_type: n,
      obu_extension_flag: i,
      obu_has_size_field: s,
      obu_extension_header: o
    };
  }
  obuExtensionHeader() {
    const t = this.f(3), n = this.f(2);
    return this.skip(3), { temporal_id: t, spatial_id: n };
  }
  sequenceHeaderObu() {
    const t = this.f(3), n = !!this.f1(), i = !!this.f1();
    let s = !1, o, l = !1, d, f = !1, p = 0;
    const m = [], b = [], h = [], y = [], v = [];
    let T, S;
    if (i)
      m[0] = 0, b[0] = this.f(5), h[0] = 0, y[0] = !1, v[0] = !1;
    else {
      s = !!this.f1(), s && (o = this.timingInfo(), l = !!this.f1(), l && (d = this.decoderModelInfo(), T = [])), f = !!this.f1(), f && (S = []), p = this.f(5);
      for (let ae = 0; ae <= p; ae += 1)
        m[ae] = this.f(12), b[ae] = this.f(5), b[ae] > 7 ? h[ae] = this.f1() : h[ae] = 0, l ? (y[ae] = !!this.f1(), y[ae] && (T[ae] = this.operatingParametersInfo(d))) : y[ae] = !1, f && (v[ae] = !!this.f1(), v[ae] && (S[ae] = this.f(4)));
    }
    const z = this.chooseOperatingPoint();
    c(this, Vt, m[z]);
    const C = this.f(4), D = this.f(4), k = this.f(C + 1), H = this.f(D + 1);
    let R = !1, I, w;
    i || (R = !!this.f1(), R && (I = this.f(4), w = this.f(3)));
    const N = !!this.f1(), x = !!this.f1(), _ = !!this.f1();
    let F = !1, P = !1, A = !1, X = !1, V = !1, q = !1, $ = !1, ne = !1, ee = Z.SelectScreenContentTools, le = !1, ie = Z.SelectIntegerMv, se;
    i || (F = !!this.f1(), P = !!this.f1(), A = !!this.f1(), X = !!this.f1(), V = !!this.f1(), V && (q = !!this.f1(), $ = !!this.f1()), ne = !!this.f1(), ne || (ee = this.f1()), ee > 0 && (le = !!this.f1(), le || (ie = this.f1())), V && (se = this.f(3)));
    const He = !!this.f1(), mi = !!this.f1(), Xr = !!this.f1(), Cr = this.colorConfig(t), Ir = !!this.f1();
    return {
      seq_profile: t,
      still_picture: n,
      reduced_still_picture_header: i,
      timing_info_present_flag: s,
      timing_info: o,
      decoder_model_info_present_flag: l,
      decoder_model_info: d,
      initial_display_delay_present_flag: f,
      initial_display_delay_minus_1: S,
      operating_points_cnt_minus_1: p,
      operating_point_idc: m,
      seq_level_idx: b,
      seq_tier: h,
      decoder_model_present_for_this_op: y,
      operating_parameters_info: T,
      initial_display_delay_present_for_this_op: v,
      frame_width_bits_minus_1: C,
      frame_height_bits_minus_1: D,
      max_frame_width_minus_1: k,
      max_frame_height_minus_1: H,
      frame_id_numbers_present_flag: R,
      delta_frame_id_length_minus_2: I,
      additional_frame_id_length_minus_1: w,
      use_128x128_superblock: N,
      enable_filter_intra: x,
      enable_intra_edge_filter: _,
      enable_interintra_compound: F,
      enable_masked_compound: P,
      enable_warped_motion: A,
      enable_dual_filter: X,
      enable_order_hint: V,
      enable_jnt_comp: q,
      enable_ref_frame_mvs: $,
      seq_choose_screen_content_tools: ne,
      seq_force_screen_content_tools: ee,
      seq_choose_integer_mv: le,
      seq_force_integer_mv: ie,
      order_hint_bits_minus_1: se,
      enable_superres: He,
      enable_cdef: mi,
      enable_restoration: Xr,
      color_config: Cr,
      film_grain_params_present: Ir
    };
  }
  searchSequenceHeaderObu() {
    for (; !this.ended; ) {
      const t = this.openBitstreamUnit();
      if (t && t.sequence_header_obu)
        return t.sequence_header_obu;
    }
  }
  timingInfo() {
    const t = this.f(32), n = this.f(32), i = !!this.f1();
    let s;
    return i && (s = this.uvlc()), {
      num_units_in_display_tick: t,
      time_scale: n,
      equal_picture_interval: i,
      num_ticks_per_picture_minus_1: s
    };
  }
  decoderModelInfo() {
    const t = this.f(5), n = this.f(32), i = this.f(5), s = this.f(5);
    return {
      buffer_delay_length_minus_1: t,
      num_units_in_decoding_tick: n,
      buffer_removal_time_length_minus_1: i,
      frame_presentation_time_length_minus_1: s
    };
  }
  operatingParametersInfo(t) {
    const n = t.buffer_delay_length_minus_1 + 1, i = this.f(n), s = this.f(n), o = !!this.f1();
    return {
      decoder_buffer_delay: i,
      encoder_buffer_delay: s,
      low_delay_mode_flag: o
    };
  }
  chooseOperatingPoint() {
    return 0;
  }
  colorConfig(t) {
    const n = !!this.f1();
    let i = !1, s = 8;
    t === 2 && n ? (i = !!this.f1(), s = i ? 12 : 10) : t <= 2 && (s = n ? 10 : 8);
    let o = !1;
    t === 1 && (o = !!this.f1());
    const l = !!this.f1();
    let d = Z.ColorPrimaries.Unspecified, f = Z.TransferCharacteristics.Unspecified, p = Z.MatrixCoefficients.Unspecified;
    l && (d = this.f(8), f = this.f(8), p = this.f(8));
    let m = !1, b, h, y = 0, v = !1;
    if (o)
      m = !!this.f1(), b = !0, h = !0;
    else {
      if (d === Z.ColorPrimaries.Bt709 && f === Z.TransferCharacteristics.Srgb && p === Z.MatrixCoefficients.Identity)
        m = !0, b = !1, h = !1;
      else {
        switch (m = !!this.f1(), t) {
          case 0:
            b = !0, h = !0;
            break;
          case 1:
            b = !1, h = !1;
            break;
          default:
            s == 12 ? (b = !!this.f1(), b ? h = !!this.f1() : h = !1) : (b = !0, h = !1);
            break;
        }
        b && h && (y = this.f(2));
      }
      v = !!this.f1();
    }
    return {
      high_bitdepth: n,
      twelve_bit: i,
      BitDepth: s,
      mono_chrome: o,
      color_description_present_flag: l,
      color_primaries: d,
      transfer_characteristics: f,
      matrix_coefficients: p,
      color_range: m,
      subsampling_x: b,
      subsampling_y: h,
      chroma_sample_position: y,
      separate_uv_delta_q: v
    };
  }
};
Mt = new WeakMap(), Vt = new WeakMap(), E(Z, "ObuType", ku), E(Z, "ColorPrimaries", Ou), E(Z, "TransferCharacteristics", Mu), E(Z, "MatrixCoefficients", Vu), E(Z, "SelectScreenContentTools", 2), E(Z, "SelectIntegerMv", 2);
let vt = Z;
function* Ka(r) {
  let e = -1, t = 0, n = !1;
  for (let i = 0; i < r.length; i += 1) {
    const s = r[i];
    if (n) {
      if (s > 3)
        throw new Error("Invalid data");
      n = !1;
      continue;
    }
    if (s === 0) {
      t += 1;
      continue;
    }
    const o = t;
    if (t = 0, e === -1) {
      if (o >= 2 && s === 1) {
        e = i + 1;
        continue;
      }
      throw new Error("Invalid data");
    }
    if (!(o < 2)) {
      if (s === 1) {
        yield r.subarray(e, i - o), e = i + 1;
        continue;
      }
      if (o > 2)
        throw new Error("Invalid data");
      switch (s) {
        case 2:
          throw new Error("Invalid data");
        case 3:
          n = !0;
          break;
      }
    }
  }
  if (n)
    throw new Error("Invalid data");
  yield r.subarray(e, r.length);
}
var xr, jt, qt, $e, we, re, et, G, er, Nr, gs, Ts;
class Wi {
  constructor(e) {
    u(this, G);
    u(this, xr);
    // logical length is `#byteLength * 8 + (7 - #stopBitIndex)`
    u(this, jt);
    u(this, qt);
    u(this, $e, 0);
    // logical position is `#bytePosition * 8 + (7 - #bitPosition)`
    u(this, we, 0);
    u(this, re, 7);
    u(this, et, 0);
    c(this, xr, e);
    for (let t = e.length - 1; t >= 0; t -= 1) {
      if (a(this, xr)[t] === 0)
        continue;
      const n = e[t];
      for (let i = 0; i < 8; i += 1)
        if ((n >> i & 1) === 1) {
          c(this, jt, t), c(this, qt, i), L(this, G, er).call(this);
          return;
        }
    }
    throw new Error("Stop bit not found");
  }
  get byteLength() {
    return a(this, jt);
  }
  get stopBitIndex() {
    return a(this, qt);
  }
  get bytePosition() {
    return a(this, we);
  }
  get bitPosition() {
    return a(this, re);
  }
  get ended() {
    return a(this, we) >= a(this, jt) && a(this, re) <= a(this, qt);
  }
  next() {
    if (this.ended)
      throw new Error("Bit index out of bounds");
    const e = a(this, et) >> a(this, re) & 1;
    return c(this, re, a(this, re) - 1), a(this, re) < 0 && (c(this, we, a(this, we) + 1), c(this, re, 7), L(this, G, er).call(this)), e;
  }
  read(e) {
    if (e > 32)
      throw new Error("Read length too large");
    let t = 0;
    for (let n = 0; n < e; n += 1)
      t = t << 1 | this.next();
    return t;
  }
  skip(e) {
    if (e <= a(this, re) + 1) {
      c(this, re, a(this, re) - e), L(this, G, Nr).call(this);
      return;
    }
    for (e -= a(this, re) + 1, c(this, we, a(this, we) + 1), c(this, re, 7), L(this, G, er).call(this), L(this, G, Nr).call(this); e >= 8; e -= 8)
      c(this, we, a(this, we) + 1), L(this, G, er).call(this), L(this, G, Nr).call(this);
    c(this, re, 7 - e), L(this, G, Nr).call(this);
  }
  decodeExponentialGolombNumber() {
    let e = 0;
    for (; this.next() === 0; )
      e += 1;
    return e === 0 ? 0 : (1 << e | this.read(e)) - 1;
  }
  peek(e) {
    const t = L(this, G, gs).call(this), n = this.read(e);
    return L(this, G, Ts).call(this, t), n;
  }
  readBytes(e) {
    const t = new Uint8Array(e);
    for (let n = 0; n < e; n += 1)
      t[n] = this.read(8);
    return t;
  }
  peekBytes(e) {
    const t = L(this, G, gs).call(this), n = this.readBytes(e);
    return L(this, G, Ts).call(this, t), n;
  }
}
xr = new WeakMap(), jt = new WeakMap(), qt = new WeakMap(), $e = new WeakMap(), we = new WeakMap(), re = new WeakMap(), et = new WeakMap(), G = new WeakSet(), er = function() {
  if (c(this, et, a(this, xr)[a(this, we)]), a(this, $e) === 2 && a(this, et) === 3) {
    c(this, $e, 0), c(this, we, a(this, we) + 1), L(this, G, er).call(this);
    return;
  }
  a(this, et) === 0 ? c(this, $e, a(this, $e) + 1) : c(this, $e, 0);
}, /**
 * Throws an error if the current position is invalid for `skip`.
 *
 * Usually it will throw if `ended` is `true`,
 * except when the bit position is at the stop bit,
 * in which case `ended` will be `true`, but it won't throw.
 * `skip` can skip all remaining bits, and stop at the end position.
 * The next `next` call will throw since there is no more bits to read.
 */
Nr = function() {
  if (a(this, we) >= a(this, jt) && a(this, re) < a(this, qt))
    throw new Error("Bit index out of bounds");
}, gs = function() {
  return {
    zeroCount: a(this, $e),
    bytePosition: a(this, we),
    bitPosition: a(this, re),
    byte: a(this, et)
  };
}, Ts = function(e) {
  c(this, $e, e.zeroCount), c(this, we, e.bytePosition), c(this, re, e.bitPosition), c(this, et, e.byte);
};
function ju(r) {
  const e = new Wi(r);
  if (e.next() !== 0)
    throw new Error("Invalid data");
  const t = e.read(2);
  if (e.read(5) !== 7)
    throw new Error("Invalid data");
  if (t === 0)
    throw new Error("Invalid data");
  const i = e.read(8), s = e.peek(8), o = !!e.next(), l = !!e.next(), d = !!e.next(), f = !!e.next(), p = !!e.next(), m = !!e.next();
  if (e.read(2) !== 0)
    throw new Error("Invalid data");
  const b = e.read(8), h = e.decodeExponentialGolombNumber();
  if (i === 100 || i === 110 || i === 122 || i === 244 || i === 44 || i === 83 || i === 86 || i === 118 || i === 128 || i === 138 || i === 139 || i === 134) {
    const R = e.decodeExponentialGolombNumber();
    if (R === 3 && e.next(), e.decodeExponentialGolombNumber(), e.decodeExponentialGolombNumber(), e.next(), !!e.next())
      for (let w = 0; w < (R !== 3 ? 8 : 12); w += 1)
        e.next();
  }
  e.decodeExponentialGolombNumber();
  const y = e.decodeExponentialGolombNumber();
  if (y === 0)
    e.decodeExponentialGolombNumber();
  else if (y === 1) {
    e.next(), e.decodeExponentialGolombNumber(), e.decodeExponentialGolombNumber();
    const R = e.decodeExponentialGolombNumber();
    for (let I = 0; I < R; I += 1)
      e.decodeExponentialGolombNumber();
  }
  e.decodeExponentialGolombNumber(), e.next();
  const v = e.decodeExponentialGolombNumber(), T = e.decodeExponentialGolombNumber(), S = e.next();
  S || e.next(), e.next();
  const z = !!e.next();
  let C, D, k, H;
  return z ? (C = e.decodeExponentialGolombNumber(), D = e.decodeExponentialGolombNumber(), k = e.decodeExponentialGolombNumber(), H = e.decodeExponentialGolombNumber()) : (C = 0, D = 0, k = 0, H = 0), e.next(), {
    profile_idc: i,
    constraint_set: s,
    constraint_set0_flag: o,
    constraint_set1_flag: l,
    constraint_set2_flag: d,
    constraint_set3_flag: f,
    constraint_set4_flag: p,
    constraint_set5_flag: m,
    level_idc: b,
    seq_parameter_set_id: h,
    pic_width_in_mbs_minus1: v,
    pic_height_in_map_units_minus1: T,
    frame_mbs_only_flag: S,
    frame_cropping_flag: z,
    frame_crop_left_offset: C,
    frame_crop_right_offset: D,
    frame_crop_top_offset: k,
    frame_crop_bottom_offset: H
  };
}
function qu(r) {
  let e, t;
  for (const n of Ka(r))
    switch (n[0] & 31) {
      case 7:
        if (e = n, t)
          return {
            sequenceParameterSet: e,
            pictureParameterSet: t
          };
        break;
      case 8:
        if (t = n, e)
          return {
            sequenceParameterSet: e,
            pictureParameterSet: t
          };
        break;
    }
  throw new Error("Invalid data");
}
function Qa(r) {
  const { sequenceParameterSet: e, pictureParameterSet: t } = qu(r), { profile_idc: n, constraint_set: i, level_idc: s, pic_width_in_mbs_minus1: o, pic_height_in_map_units_minus1: l, frame_mbs_only_flag: d, frame_crop_left_offset: f, frame_crop_right_offset: p, frame_crop_top_offset: m, frame_crop_bottom_offset: b } = ju(e), h = (o + 1) * 16, y = (l + 1) * (2 - d) * 16, v = f * 2, T = p * 2, S = m * 2, z = b * 2, C = h - v - T, D = y - S - z;
  return {
    pictureParameterSet: t,
    sequenceParameterSet: e,
    profileIndex: n,
    constraintSet: i,
    levelIndex: s,
    encodedWidth: h,
    encodedHeight: y,
    cropLeft: v,
    cropRight: T,
    cropTop: S,
    cropBottom: z,
    croppedWidth: C,
    croppedHeight: D
  };
}
function Uu(r) {
  switch (r) {
    case 0:
    case 3:
      return 1;
    case 1:
    case 2:
      return 2;
    default:
      throw new Error("Invalid chroma_format_idc");
  }
}
function Bu(r) {
  switch (r) {
    case 0:
    case 2:
    case 3:
      return 1;
    case 1:
      return 2;
    default:
      throw new Error("Invalid chroma_format_idc");
  }
}
function Wu(r) {
  const e = new Wi(r);
  if (e.next() !== 0)
    throw new Error("Invalid NALU header");
  const t = e.read(6), n = e.read(6), i = e.read(3);
  return {
    nal_unit_type: t,
    nuh_layer_id: n,
    nuh_temporal_id_plus1: i
  };
}
function Fu(r) {
  const e = new Wi(r), t = e.read(4), n = !!e.next(), i = !!e.next(), s = e.read(6), o = e.read(3), l = !!e.next();
  e.skip(16);
  const d = _a(e, !0, o), f = !!e.next(), p = [], m = [], b = [];
  for (let N = f ? 0 : o; N <= o; N += 1)
    p[N] = e.decodeExponentialGolombNumber(), m[N] = e.decodeExponentialGolombNumber(), b[N] = e.decodeExponentialGolombNumber();
  const h = e.read(6), y = e.decodeExponentialGolombNumber(), v = [];
  for (let N = 1; N <= y; N += 1) {
    v[N] = [];
    for (let x = 0; x <= h; x += 1)
      v[N][x] = !!e.next();
  }
  const T = !!e.next();
  let S, z, C, D, k, H, R, I;
  if (T) {
    S = e.read(32), z = e.read(32), C = !!e.next(), C && (D = e.decodeExponentialGolombNumber()), k = e.decodeExponentialGolombNumber(), H = [], R = [!0], I = [];
    for (let N = 0; N < k; N += 1)
      H[N] = e.decodeExponentialGolombNumber(), N > 0 && (R[N] = !!e.next()), I[N] = $a(e, R[N], o);
  }
  const w = !!e.next();
  return {
    vps_video_parameter_set_id: t,
    vps_base_layer_internal_flag: n,
    vps_base_layer_available_flag: i,
    vps_max_layers_minus1: s,
    vps_max_sub_layers_minus1: o,
    vps_temporal_id_nesting_flag: l,
    profileTierLevel: d,
    vps_sub_layer_ordering_info_present_flag: f,
    vps_max_dec_pic_buffering_minus1: p,
    vps_max_num_reorder_pics: m,
    vps_max_latency_increase_plus1: b,
    vps_max_layer_id: h,
    vps_num_layer_sets_minus1: y,
    layer_id_included_flag: v,
    vps_timing_info_present_flag: T,
    vps_num_units_in_tick: S,
    vps_time_scale: z,
    vps_poc_proportional_to_timing_flag: C,
    vps_num_ticks_poc_diff_one_minus1: D,
    vps_num_hrd_parameters: k,
    hrd_layer_set_idx: H,
    cprms_present_flag: R,
    hrdParameters: I,
    vps_extension_flag: w
  };
}
function Zu(r) {
  const e = new Wi(r), t = e.read(4), n = e.read(3), i = !!e.next(), s = _a(e, !0, n), o = e.decodeExponentialGolombNumber(), l = e.decodeExponentialGolombNumber();
  let d;
  l === 3 && (d = !!e.next());
  const f = e.decodeExponentialGolombNumber(), p = e.decodeExponentialGolombNumber(), m = !!e.next();
  let b, h, y, v;
  m && (b = e.decodeExponentialGolombNumber(), h = e.decodeExponentialGolombNumber(), y = e.decodeExponentialGolombNumber(), v = e.decodeExponentialGolombNumber());
  const T = e.decodeExponentialGolombNumber(), S = e.decodeExponentialGolombNumber(), z = e.decodeExponentialGolombNumber(), C = [], D = [], k = [], H = !!e.next();
  for (let J = H ? 0 : n; J <= n; J += 1)
    C[J] = e.decodeExponentialGolombNumber(), D[J] = e.decodeExponentialGolombNumber(), k[J] = e.decodeExponentialGolombNumber();
  const R = e.decodeExponentialGolombNumber(), I = e.decodeExponentialGolombNumber(), w = e.decodeExponentialGolombNumber(), N = e.decodeExponentialGolombNumber(), x = e.decodeExponentialGolombNumber(), _ = e.decodeExponentialGolombNumber(), F = !!e.next();
  let P, A;
  F && (P = !!e.next(), P && (A = Gu(e)));
  const X = !!e.next(), V = !!e.next(), q = !!e.next();
  let $, ne, ee, le, ie;
  q && ($ = e.read(4), ne = e.read(4), ee = e.read(4), le = e.read(4), ie = !!e.next());
  const se = e.decodeExponentialGolombNumber(), He = [];
  for (let J = 0; J < se; J += 1)
    He[J] = Yu(e, J, se, He);
  const mi = !!e.next();
  let Xr, Cr, Ir;
  if (mi) {
    Xr = e.decodeExponentialGolombNumber(), Cr = [], Ir = [];
    for (let J = 0; J < Xr; J += 1)
      Cr[J] = e.read(z + 4), Ir[J] = !!e.next();
  }
  const ae = !!e.next(), Po = !!e.next(), js = !!e.next();
  let qs;
  js && (qs = Ju(e, n));
  const Us = !!e.next();
  let Fi, Zi, Gi, Yi, Ji;
  if (Us && (Fi = !!e.next(), Zi = !!e.next(), Gi = !!e.next(), Yi = !!e.next(), Ji = e.read(4)), Fi)
    throw new Error("Not implemented");
  let Bs;
  Zi && (Bs = Qu(e));
  let Ws;
  if (Gi && (Ws = _u(e)), Yi)
    throw new Error("Not implemented");
  let Ki;
  if (Ji) {
    Ki = [];
    let J = 0;
    for (; !e.ended; )
      Ki[J] = !!e.next(), J += 1;
  }
  return {
    sps_video_parameter_set_id: t,
    sps_max_sub_layers_minus1: n,
    sps_temporal_id_nesting_flag: i,
    profileTierLevel: s,
    sps_seq_parameter_set_id: o,
    chroma_format_idc: l,
    separate_colour_plane_flag: d,
    pic_width_in_luma_samples: f,
    pic_height_in_luma_samples: p,
    conformance_window_flag: m,
    conf_win_left_offset: b,
    conf_win_right_offset: h,
    conf_win_top_offset: y,
    conf_win_bottom_offset: v,
    bit_depth_luma_minus8: T,
    bit_depth_chroma_minus8: S,
    log2_max_pic_order_cnt_lsb_minus4: z,
    sps_sub_layer_ordering_info_present_flag: H,
    sps_max_dec_pic_buffering_minus1: C,
    sps_max_num_reorder_pics: D,
    sps_max_latency_increase_plus1: k,
    log2_min_luma_coding_block_size_minus3: R,
    log2_diff_max_min_luma_coding_block_size: I,
    log2_min_luma_transform_block_size_minus2: w,
    log2_diff_max_min_luma_transform_block_size: N,
    max_transform_hierarchy_depth_inter: x,
    max_transform_hierarchy_depth_intra: _,
    scaling_list_enabled_flag: F,
    sps_scaling_list_data_present_flag: P,
    scalingListData: A,
    amp_enabled_flag: X,
    sample_adaptive_offset_enabled_flag: V,
    pcm_enabled_flag: q,
    pcm_sample_bit_depth_luma_minus1: $,
    pcm_sample_bit_depth_chroma_minus1: ne,
    log2_min_pcm_luma_coding_block_size_minus3: ee,
    log2_diff_max_min_pcm_luma_coding_block_size: le,
    pcm_loop_filter_disabled_flag: ie,
    num_short_term_ref_pic_sets: se,
    shortTermRefPicSets: He,
    long_term_ref_pics_present_flag: mi,
    num_long_term_ref_pics_sps: Xr,
    lt_ref_pic_poc_lsb_sps: Cr,
    used_by_curr_pic_lt_sps_flag: Ir,
    sps_temporal_mvp_enabled_flag: ae,
    strong_intra_smoothing_enabled_flag: Po,
    vui_parameters_present_flag: js,
    vuiParameters: qs,
    sps_extension_present_flag: Us,
    sps_range_extension_flag: Fi,
    sps_multilayer_extension_flag: Zi,
    sps_3d_extension_flag: Gi,
    sps_scc_extension_flag: Yi,
    sps_extension_4bits: Ji,
    spsMultilayerExtension: Bs,
    sps3dExtension: Ws,
    sps_extension_data_flag: Ki
  };
}
function aa(r) {
  const e = r.read(2), t = !!r.next(), n = r.read(5), i = r.peekBytes(4), s = [];
  for (let H = 0; H < 32; H += 1)
    s[H] = !!r.next();
  const o = r.peekBytes(6), l = !!r.next(), d = !!r.next(), f = !!r.next(), p = !!r.next();
  let m, b, h, y, v, T, S, z, C, D;
  n === 4 || s[4] || n === 5 || s[5] || n === 6 || s[6] || n === 7 || s[7] || n === 8 || s[8] || n === 9 || s[9] || n === 10 || s[10] || n === 11 || s[11] ? (m = !!r.next(), b = !!r.next(), h = !!r.next(), y = !!r.next(), v = !!r.next(), T = !!r.next(), S = !!r.next(), z = !!r.next(), C = !!r.next(), n === 5 || s[5] || n === 9 || s[9] || n === 10 || s[10] || n === 11 || s[11] ? (D = !!r.next(), r.skip(33)) : r.skip(34)) : n === 2 || s[2] ? (r.skip(7), z = !!r.next(), r.skip(35)) : r.skip(43);
  let k;
  return n === 1 || s[1] || n === 2 || s[2] || n === 3 || s[3] || n === 4 || s[4] || n === 5 || s[5] || n === 9 || s[9] || n === 11 || s[11] ? k = !!r.next() : r.skip(1), {
    profile_space: e,
    tier_flag: t,
    profile_idc: n,
    profileCompatibilitySet: i,
    profile_compatibility_flag: s,
    constraintSet: o,
    progressive_source_flag: l,
    interlaced_source_flag: d,
    non_packed_constraint_flag: f,
    frame_only_constraint_flag: p,
    max_12bit_constraint_flag: m,
    max_10bit_constraint_flag: b,
    max_8bit_constraint_flag: h,
    max_422chroma_constraint_flag: y,
    max_420chroma_constraint_flag: v,
    max_monochrome_constraint_flag: T,
    intra_constraint_flag: S,
    one_picture_only_constraint_flag: z,
    lower_bit_rate_constraint_flag: C,
    max_14bit_constraint_flag: D,
    inbld_flag: k
  };
}
function _a(r, e, t) {
  let n;
  n = aa(r);
  const i = r.read(8), s = [], o = [];
  for (let f = 0; f < t; f += 1)
    s[f] = !!r.next(), o[f] = !!r.next();
  if (t > 0)
    for (let f = t; f < 8; f += 1)
      r.read(2);
  const l = [], d = [];
  for (let f = 0; f < t; f += 1)
    s[f] && (l[f] = aa(r)), o[f] && (d[f] = r.read(8));
  return {
    generalProfileTier: n,
    general_level_idc: i,
    sub_layer_profile_present_flag: s,
    sub_layer_level_present_flag: o,
    subLayerProfileTier: l,
    sub_layer_level_idc: d
  };
}
function Gu(r) {
  const e = [];
  for (let t = 0; t < 4; t += 1) {
    e[t] = [];
    for (let n = 0; n < 6; n += t === 3 ? 3 : 1)
      if (!!!r.next())
        r.decodeExponentialGolombNumber();
      else {
        let s = 8;
        const o = Math.min(64, 1 << 4 + (t << 1));
        t > 1 && (s = r.decodeExponentialGolombNumber() + 8), e[t][n] = [];
        for (let l = 0; l < o; l += 1) {
          const d = r.decodeExponentialGolombNumber();
          s = (s + d + 256) % 256, e[t][n][l] = s;
        }
      }
  }
  return e;
}
function Yu(r, e, t, n) {
  let i = !1;
  e !== 0 && (i = !!r.next());
  let s = 0, o = !1, l = 0;
  const d = [], f = [];
  let p = 0, m = 0;
  const b = [], h = [], y = [], v = [];
  if (i) {
    e === t && (s = r.decodeExponentialGolombNumber()), o = !!r.next(), l = r.decodeExponentialGolombNumber();
    const T = e - (s + 1), S = n[T], z = S.num_negative_pics + S.num_positive_pics;
    for (let x = 0; x <= z; x += 1)
      d[x] = !!r.next(), d[x] ? f[x] = !0 : f[x] = !!r.next();
    const C = (1 - 2 * Number(o)) * (l + 1), D = [], k = [], H = [], R = [];
    let I = 0;
    for (let x = 0; x < S.num_negative_pics; x += 1)
      I -= S.delta_poc_s0_minus1[x] + 1, D[x] = I;
    I = 0;
    for (let x = 0; x < S.num_positive_pics; x += 1)
      I += S.delta_poc_s1_minus1[x] + 1, k[x] = I;
    let w = 0;
    if (S.num_positive_pics > 0)
      for (let x = S.num_positive_pics - 1; x >= 0; x -= 1)
        I = k[x] + C, I < 0 && f[S.num_negative_pics + x] && (H[w] = I, h[w] = d[S.num_negative_pics + x], w += 1);
    C < 0 && f[z] && (H[w] = C, h[w] = d[z], w += 1);
    for (let x = 0; x < S.num_negative_pics; x += 1)
      I = D[x] + C, I < 0 && f[x] && (H[w] = I, h[w] = d[x], w += 1);
    p = w;
    let N = 0;
    for (w = 0; w < p; w += 1) {
      const x = H[w];
      b[w] = -(x - N - 1), N = x;
    }
    if (w = 0, S.num_negative_pics > 0)
      for (let x = S.num_negative_pics - 1; x >= 0; x -= 1)
        I = D[x] + C, I > 0 && f[x] && (R[w] = I, v[w] = d[x], w += 1);
    C > 0 && f[z] && (R[w] = C, v[w] = d[z], w += 1);
    for (let x = 0; x < S.num_positive_pics; x += 1)
      I = k[x] + C, I > 0 && f[S.num_negative_pics + x] && (R[w] = I, v[w] = d[S.num_negative_pics + x], w += 1);
    for (m = w, N = 0, w = 0; w < m; w += 1) {
      const x = R[w];
      y[w] = x - N - 1, N = x;
    }
  } else {
    p = r.decodeExponentialGolombNumber(), m = r.decodeExponentialGolombNumber();
    for (let T = 0; T < p; T += 1)
      b[T] = r.decodeExponentialGolombNumber(), h[T] = !!r.next();
    for (let T = 0; T < m; T += 1)
      y[T] = r.decodeExponentialGolombNumber(), v[T] = !!r.next();
  }
  return {
    stRpsIdx: e,
    num_short_term_ref_pic_sets: t,
    inter_ref_pic_set_prediction_flag: i,
    delta_idx_minus1: s,
    delta_rps_sign: o,
    abs_delta_rps_minus1: l,
    used_by_curr_pic_flag: d,
    use_delta_flag: f,
    num_negative_pics: p,
    num_positive_pics: m,
    delta_poc_s0_minus1: b,
    used_by_curr_pic_s0_flag: h,
    delta_poc_s1_minus1: y,
    used_by_curr_pic_s1_flag: v
  };
}
function Ju(r, e) {
  const t = !!r.next();
  let n, i, s;
  t && (n = r.read(8), n === 255 && (i = r.read(16), s = r.read(16)));
  const o = !!r.next();
  let l;
  o && (l = !!r.next());
  const d = !!r.next();
  let f, p, m, b, h, y;
  d && (f = r.read(3), p = !!r.next(), m = !!r.next(), m && (b = r.read(8), h = r.read(8), y = r.read(8)));
  const v = !!r.next();
  let T, S;
  v && (T = r.decodeExponentialGolombNumber(), S = r.decodeExponentialGolombNumber());
  const z = !!r.next(), C = !!r.next(), D = !!r.next(), k = !!r.next();
  let H, R, I, w;
  k && (H = r.decodeExponentialGolombNumber(), R = r.decodeExponentialGolombNumber(), I = r.decodeExponentialGolombNumber(), w = r.decodeExponentialGolombNumber());
  const N = !!r.next();
  let x, _, F, P, A, X;
  N && (x = r.read(32), _ = r.read(32), F = !!r.next(), F && (P = r.decodeExponentialGolombNumber()), A = !!r.next(), A && (X = $a(r, !0, e)));
  const V = !!r.next();
  let q, $, ne, ee, le, ie, se, He;
  return V && (q = !!r.next(), $ = !!r.next(), ne = !!r.next(), ee = r.decodeExponentialGolombNumber(), le = r.decodeExponentialGolombNumber(), ie = r.decodeExponentialGolombNumber(), se = r.decodeExponentialGolombNumber(), He = r.decodeExponentialGolombNumber()), {
    aspect_ratio_info_present_flag: t,
    aspect_ratio_idc: n,
    sar_width: i,
    sar_height: s,
    overscan_info_present_flag: o,
    overscan_appropriate_flag: l,
    video_signal_type_present_flag: d,
    video_format: f,
    video_full_range_flag: p,
    colour_description_present_flag: m,
    colour_primaries: b,
    transfer_characteristics: h,
    matrix_coeffs: y,
    chroma_loc_info_present_flag: v,
    chroma_sample_loc_type_top_field: T,
    chroma_sample_loc_type_bottom_field: S,
    neutral_chroma_indication_flag: z,
    field_seq_flag: C,
    frame_field_info_present_flag: D,
    default_display_window_flag: k,
    def_disp_win_left_offset: H,
    def_disp_win_right_offset: R,
    def_disp_win_top_offset: I,
    def_disp_win_bottom_offset: w,
    vui_timing_info_present_flag: N,
    vui_num_units_in_tick: x,
    vui_time_scale: _,
    vui_poc_proportional_to_timing_flag: F,
    vui_num_ticks_poc_diff_one_minus1: P,
    vui_hrd_parameters_present_flag: A,
    vui_hrd_parameters: X,
    bitstream_restriction_flag: V,
    tiles_fixed_structure_flag: q,
    motion_vectors_over_pic_boundaries_flag: $,
    restricted_ref_pic_lists_flag: ne,
    min_spatial_segmentation_idc: ee,
    max_bytes_per_pic_denom: le,
    max_bits_per_min_cu_denom: ie,
    log2_max_mv_length_horizontal: se,
    log2_max_mv_length_vertical: He
  };
}
function $a(r, e, t) {
  let n, i, s, o, l, d, f, p, m, b, h, y, v;
  e && (n = !!r.next(), i = !!r.next(), (n || i) && (s = !!r.next(), s && (o = r.read(8), l = r.read(5), d = !!r.next(), f = r.read(5)), p = r.read(4), m = r.read(4), s && (b = r.read(4)), h = r.read(5), y = r.read(5), v = r.read(5)));
  const T = [], S = [], z = [], C = [], D = [], k = [], H = [];
  for (let R = 0; R <= t; R += 1)
    T[R] = !!r.next(), T[R] || (S[R] = !!r.next()), S[R] ? z[R] = r.decodeExponentialGolombNumber() : C[R] = !!r.next(), C[R] || (D[R] = r.decodeExponentialGolombNumber()), n && (k[R] = oa(r, R, ca(D[R]))), i && (H[R] = oa(r, R, ca(D[R])));
  return {
    nal_hrd_parameters_present_flag: n,
    vcl_hrd_parameters_present_flag: i,
    sub_pic_hrd_params_present_flag: s,
    tick_divisor_minus2: o,
    du_cpb_removal_delay_increment_length_minus1: l,
    sub_pic_cpb_params_in_pic_timing_sei_flag: d,
    dpb_output_delay_du_length_minus1: f,
    bit_rate_scale: p,
    cpb_size_scale: m,
    cpb_size_du_scale: b,
    initial_cpb_removal_delay_length_minus1: h,
    au_cpb_removal_delay_length_minus1: y,
    dpb_output_delay_length_minus1: v,
    fixed_pic_rate_general_flag: T,
    fixed_pic_rate_within_cvs_flag: S,
    elemental_duration_in_tc_minus1: z,
    low_delay_hrd_flag: C,
    cpb_cnt_minus1: D,
    nalHrdParameters: k,
    vclHrdParameters: H
  };
}
function oa(r, e, t) {
  const n = [], i = [], s = [], o = [], l = [];
  for (let d = 0; d < t; d += 1)
    n[d] = r.decodeExponentialGolombNumber(), i[d] = r.decodeExponentialGolombNumber(), e > 0 && (l[d] = !!r.next());
  return {
    bit_rate_value_minus1: n,
    cpb_size_value_minus1: i,
    cpb_size_du_value_minus1: s,
    bit_rate_du_value_minus1: o,
    cbr_flag: l
  };
}
function ca(r) {
  return r + 1;
}
function Ku(r) {
  let e, t, n, i = 0;
  for (const s of Ka(r)) {
    const o = Wu(s), l = {
      ...o,
      data: s,
      rbsp: s.subarray(2)
    };
    switch (o.nal_unit_type) {
      case 32:
        e = l;
        break;
      case 33:
        t = l;
        break;
      case 34:
        n = l;
        break;
      default:
        continue;
    }
    if (i += 1, i === 3)
      return {
        videoParameterSet: e,
        sequenceParameterSet: t,
        pictureParameterSet: n
      };
  }
  throw new Error("Invalid data");
}
function Qu(r) {
  return {
    inter_view_mv_vert_constraint_flag: !!r.next()
  };
}
function _u(r) {
  const e = [], t = [];
  e[0] = !!r.next(), t[0] = !!r.next();
  const n = r.decodeExponentialGolombNumber(), i = !!r.next(), s = !!r.next(), o = !!r.next(), l = !!r.next();
  e[1] = !!r.next(), t[1] = !!r.next();
  const d = !!r.next(), f = r.decodeExponentialGolombNumber(), p = !!r.next(), m = !!r.next(), b = !!r.next(), h = !!r.next(), y = !!r.next();
  return {
    iv_di_mc_enabled_flag: e,
    iv_mv_scal_enabled_flag: t,
    log2_ivmc_sub_pb_size_minus3: n,
    iv_res_pred_enabled_flag: i,
    depth_ref_enabled_flag: s,
    vsp_mc_enabled_flag: o,
    dbbp_enabled_flag: l,
    tex_mc_enabled_flag: d,
    log2_texmc_sub_pb_size_minus3: f,
    intra_contour_enabled_flag: p,
    intra_dc_only_wedge_enabled_flag: m,
    cqt_cu_part_pred_enabled_flag: b,
    inter_dc_only_enabled_flag: h,
    skip_intra_enabled_flag: y
  };
}
function eo(r) {
  const { videoParameterSet: e, sequenceParameterSet: t, pictureParameterSet: n } = Ku(r), { profileTierLevel: { generalProfileTier: { profile_space: i, tier_flag: s, profile_idc: o, profileCompatibilitySet: l, constraintSet: d }, general_level_idc: f } } = Fu(e.rbsp), { chroma_format_idc: p, pic_width_in_luma_samples: m, pic_height_in_luma_samples: b, conf_win_left_offset: h = 0, conf_win_right_offset: y = 0, conf_win_top_offset: v = 0, conf_win_bottom_offset: T = 0 } = Zu(t.rbsp), S = Uu(p), z = Bu(p), C = m - S * (h + y), D = b - z * (v + T);
  return {
    videoParameterSet: e,
    sequenceParameterSet: t,
    pictureParameterSet: n,
    generalProfileSpace: i,
    generalProfileIndex: o,
    generalProfileCompatibilitySet: l,
    generalTierFlag: s,
    generalLevelIndex: f,
    generalConstraintSet: d,
    encodedWidth: m,
    encodedHeight: b,
    cropLeft: h,
    cropRight: y,
    cropTop: v,
    cropBottom: T,
    croppedWidth: C,
    croppedHeight: D
  };
}
class $u extends Ja {
  constructor(e, t) {
    super(e, t);
  }
}
function ed(r) {
  return new Se(async (e) => {
    for (const t of r)
      await e.enqueue(t);
  });
}
function td(...r) {
  return new Se(async (e) => {
    for (const t of r) {
      const n = t.getReader();
      for (; ; ) {
        const { done: i, value: s } = await n.read();
        if (i)
          break;
        await e.enqueue(s);
      }
    }
  });
}
class Is extends Error {
  constructor(t) {
    super("scrcpy server exited prematurely");
    E(this, "output");
    this.output = t;
  }
}
var Ie, Pr, qn, Ut, Bt, Un, Bn, Wn, be, to, ro, no, io, so, ao;
const Vs = class Vs {
  constructor({ options: e, process: t, stdout: n, videoStream: i, audioStream: s, controlStream: o }) {
    u(this, be);
    u(this, Ie);
    u(this, Pr);
    u(this, qn);
    u(this, Ut);
    u(this, Bt);
    u(this, Un);
    u(this, Bn);
    u(this, Wn);
    c(this, Ie, e), c(this, Pr, t), c(this, qn, n), c(this, Un, i ? L(this, be, so).call(this, i) : void 0), c(this, Bn, s ? L(this, be, ao).call(this, s) : void 0), o && (c(this, Wn, new Nl(o.writable.getWriter(), e)), L(this, be, to).call(this, o.readable).catch(() => {
    }));
  }
  static async pushServer(e, t, n = Ul) {
    const i = await e.sync();
    try {
      await i.write({
        filename: n,
        file: t
      });
    } finally {
      await i.dispose();
    }
  }
  static async start(e, t, n) {
    let i, s;
    try {
      try {
        i = n.createConnection(e), await i.initialize();
      } catch (m) {
        if (m instanceof Xs)
          n.value.tunnelForward = !0, i = n.createConnection(e), await i.initialize();
        else
          throw i = void 0, m;
      }
      s = await e.subprocess.spawn([
        // cspell: disable-next-line
        `CLASSPATH=${t}`,
        "app_process",
        /* unused */
        "/",
        "com.genymobile.scrcpy.Server",
        n.version,
        ...n.serialize()
      ], {
        // Scrcpy server doesn't use stderr,
        // so disable Shell Protocol to simplify processing
        protocols: [kr]
      });
      const o = s.stdout.pipeThrough(new gi()).pipeThrough(new ic(`
`)), l = [], d = new pi(), f = o.pipeTo(new ze({
        write(m) {
          l.push(m);
        }
      }), {
        signal: d.signal,
        preventCancel: !0
      }).catch((m) => {
        if (!d.signal.aborted)
          throw m;
      }), p = await Promise.race([
        s.exit.then(() => {
          throw new Is(l);
        }),
        i.getStreams()
      ]);
      return d.abort(), await f, new Vs({
        options: n,
        process: s,
        stdout: td(ed(l), o),
        videoStream: p.video,
        audioStream: p.audio,
        controlStream: p.control
      });
    } catch (o) {
      throw await (s == null ? void 0 : s.kill()), o;
    } finally {
      i == null || i.dispose();
    }
  }
  /**
   * This method will modify the given `options`,
   * so don't reuse it elsewhere.
   */
  static getEncoders(e, t, n) {
    return n.setListEncoders(), n.getEncoders(e, t);
  }
  /**
   * This method will modify the given `options`,
   * so don't reuse it elsewhere.
   */
  static getDisplays(e, t, n) {
    return n.setListDisplays(), n.getDisplays(e, t);
  }
  get stdout() {
    return a(this, qn);
  }
  get exit() {
    return a(this, Pr).exit;
  }
  get screenWidth() {
    return a(this, Ut);
  }
  get screenHeight() {
    return a(this, Bt);
  }
  /**
   * Gets a `Promise` that resolves to the parsed video stream.
   *
   * On server version 2.1 and above, it will be `undefined` if
   * video is disabled by `options.video: false`.
   *
   * Note: if it's not `undefined`, it must be consumed to prevent
   * the connection from being blocked.
   */
  get videoStream() {
    return a(this, Un);
  }
  /**
   * Gets a `Promise` that resolves to the parsed audio stream.
   *
   * On server versions before 2.0, it will always be `undefined`.
   * On server version 2.0 and above, it will be `undefined` if
   * audio is disabled by `options.audio: false`.
   *
   * Note: if it's not `undefined`, it must be consumed to prevent
   * the connection from being blocked.
   */
  get audioStream() {
    return a(this, Bn);
  }
  /**
   * Gets the control message writer.
   *
   * On server version 1.22 and above, it will be `undefined` if
   * control is disabled by `options.control: false`.
   */
  get controller() {
    return a(this, Wn);
  }
  async close() {
    await a(this, Pr).kill();
  }
};
Ie = new WeakMap(), Pr = new WeakMap(), qn = new WeakMap(), Ut = new WeakMap(), Bt = new WeakMap(), Un = new WeakMap(), Bn = new WeakMap(), Wn = new WeakMap(), be = new WeakSet(), to = async function(e) {
  const t = new bt(e);
  try {
    for (; ; ) {
      let n;
      try {
        n = (await t.readExactly(1))[0];
      } catch (i) {
        if (i instanceof Ui) {
          a(this, Ie).endDeviceMessageStream();
          break;
        }
        throw i;
      }
      await a(this, Ie).parseDeviceMessage(n, t);
    }
  } catch (n) {
    a(this, Ie).endDeviceMessageStream(n), t.cancel(n).catch(() => {
    });
  }
}, ro = function(e) {
  const { croppedWidth: t, croppedHeight: n } = Qa(e);
  c(this, Ut, t), c(this, Bt, n);
}, no = function(e) {
  const { croppedWidth: t, croppedHeight: n } = eo(e);
  c(this, Ut, t), c(this, Bt, n);
}, io = function(e) {
  const n = new vt(e).searchSequenceHeaderObu();
  if (!n)
    return;
  const { max_frame_width_minus_1: i, max_frame_height_minus_1: s } = n, o = i + 1, l = s + 1;
  c(this, Ut, o), c(this, Bt, l);
}, so = async function(e) {
  const { stream: t, metadata: n } = await a(this, Ie).parseVideoStreamMetadata(e);
  return {
    stream: t.pipeThrough(a(this, Ie).createMediaStreamTransformer()).pipeThrough(new tc((i) => {
      if (i.type === "configuration")
        switch (n.codec) {
          case nt.H264:
            L(this, be, ro).call(this, i.data);
            break;
          case nt.H265:
            L(this, be, no).call(this, i.data);
            break;
        }
      else n.codec === nt.AV1 && L(this, be, io).call(this, i.data);
    })),
    metadata: n
  };
}, ao = async function(e) {
  const t = await a(this, Ie).parseAudioStreamMetadata(e);
  switch (t.type) {
    case "disabled":
    case "errored":
      return t;
    case "success":
      return {
        ...t,
        stream: t.stream.pipeThrough(a(this, Ie).createMediaStreamTransformer())
      };
    default:
      throw new Error(`Unexpected audio metadata type ${t.type}`);
  }
};
let Qt = Vs;
const rd = "scrcpy";
class oo {
  constructor(e, t) {
    E(this, "adb");
    E(this, "options");
    E(this, "socketName");
    this.adb = e, this.options = t, this.socketName = this.getSocketName();
  }
  initialize() {
  }
  getSocketName() {
    let e = "localabstract:" + rd;
    return this.options.scid !== void 0 && (e += "_" + this.options.scid.padStart(8, "0")), e;
  }
  dispose() {
  }
}
var Fn, ht, co, xi;
class nd extends oo {
  constructor() {
    super(...arguments);
    u(this, ht);
    u(this, Fn, !1);
  }
  async getStreams() {
    let { sendDummyByte: t } = this.options;
    const n = {};
    if (this.options.video) {
      const i = await L(this, ht, xi).call(this, t);
      n.video = i.readable, t = !1;
    }
    if (this.options.audio) {
      const i = await L(this, ht, xi).call(this, t);
      n.audio = i.readable, t = !1;
    }
    if (this.options.control) {
      const i = await L(this, ht, xi).call(this, t);
      n.control = i, t = !1;
    }
    return n;
  }
  dispose() {
    c(this, Fn, !0);
  }
}
Fn = new WeakMap(), ht = new WeakSet(), co = function() {
  return this.adb.createSocket(this.socketName);
}, xi = async function(t) {
  for (let n = 0; !a(this, Fn) && n < 100; n += 1)
    try {
      const i = await L(this, ht, co).call(this);
      if (t) {
        const s = new bt(i.readable);
        return await s.readExactly(1), {
          readable: s.release(),
          writable: i.writable
        };
      }
      return i;
    } catch {
      await ha(100);
    }
  throw new Error("Can't connect to server after 100 retries");
};
var Zn, Gn, gr, Pi;
class id extends oo {
  constructor() {
    super(...arguments);
    u(this, gr);
    u(this, Zn);
    u(this, Gn);
  }
  async initialize() {
    await this.adb.reverse.remove(this.socketName).catch((i) => {
      if (i instanceof Xs)
        throw i;
    });
    let t;
    const n = new Se((i) => {
      t = i;
    });
    c(this, Zn, n.getReader()), c(this, Gn, await this.adb.reverse.add(this.socketName, async (i) => {
      await t.enqueue(i);
    }));
  }
  async getStreams() {
    const t = {};
    if (this.options.video) {
      const n = await L(this, gr, Pi).call(this);
      t.video = n.readable;
    }
    if (this.options.audio) {
      const n = await L(this, gr, Pi).call(this);
      t.audio = n.readable;
    }
    if (this.options.control) {
      const n = await L(this, gr, Pi).call(this);
      t.control = n;
    }
    return t;
  }
  dispose() {
    this.adb.reverse.remove(a(this, Gn)).catch(Sa);
  }
}
Zn = new WeakMap(), Gn = new WeakMap(), gr = new WeakSet(), Pi = async function() {
  return (await a(this, Zn).read()).value;
};
class Ds extends Bl {
}
class ft extends Ds {
  static createConnection(e, t, n) {
    return n ? new nd(e, t) : new id(e, t);
  }
  static async getEncoders(e, t, n) {
    const i = await Qt.start(e, t, n), s = [];
    return await i.stdout.pipeTo(new ze({
      write: (o) => {
        const l = n.parseEncoder(o);
        l && s.push(l);
      }
    })), s;
  }
  static async getDisplays(e, t, n) {
    var i;
    try {
      throw await (await Qt.start(e, t, n)).close(), new Error("Unexpected server output");
    } catch (s) {
      if (s instanceof Is) {
        if ((i = s.output[0]) != null && i.startsWith("[server] ERROR:"))
          throw s;
        const o = [];
        for (const l of s.output) {
          const d = n.parseDisplay(l);
          d && o.push(d);
        }
        return o;
      }
      throw s;
    }
  }
  getEncoders(e, t) {
    return ft.getEncoders(e, t, this);
  }
  getDisplays(e, t) {
    return ft.getDisplays(e, t, this);
  }
  createConnection(e) {
    return ft.createConnection(e, {
      scid: void 0,
      // Not Supported
      video: !0,
      // Always enabled
      audio: !1,
      // Not Supported
      control: !0,
      // Always enabled even when `--no-control` is specified
      sendDummyByte: !0
      // Always enabled
    }, this.value.tunnelForward);
  }
}
class Hs extends Ds {
  static async getEncoders(e, t, n) {
    try {
      throw await (await Qt.start(e, t, n)).close(), new Error("Unexpected server output");
    } catch (i) {
      if (i instanceof Is) {
        const s = [];
        for (const o of i.output) {
          const l = n.parseEncoder(o);
          l && s.push(l);
        }
        return s;
      }
      throw i;
    }
  }
  async getEncoders(e, t) {
    return Hs.getEncoders(e, t, this);
  }
  getDisplays(e, t) {
    return ft.getDisplays(e, t, this);
  }
  createConnection(e) {
    return ft.createConnection(e, {
      scid: Li(this.value.scid, void 0),
      video: !0,
      // Always enabled
      audio: this.value.audio,
      control: this.value.control,
      sendDummyByte: this.value.sendDummyByte
    }, this.value.tunnelForward);
  }
}
class sd extends Ds {
  async getEncoders(e, t) {
    return Hs.getEncoders(e, t, this);
  }
  getDisplays(e, t) {
    return ft.getDisplays(e, t, this);
  }
  createConnection(e) {
    return ft.createConnection(e, {
      scid: Li(this.value.scid, void 0),
      video: this.value.video,
      audio: this.value.audio,
      control: this.value.control,
      sendDummyByte: this.value.sendDummyByte
    }, this.value.tunnelForward);
  }
}
const ad = "3.3.1", od = /* @__PURE__ */ new URL("data:application/octet-stream;base64,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", import.meta.url);
function la(r) {
  return r.toString(16).toUpperCase();
}
function ns(r) {
  return r.toString(16).toUpperCase().padStart(2, "0");
}
function Hr(r) {
  return r.toString(10).padStart(2, "0");
}
var Tr, Yn, Vi, lo;
class cd {
  constructor(e, t) {
    u(this, Vi);
    u(this, Tr);
    u(this, Yn);
    c(this, Tr, e), c(this, Yn, t);
  }
  decode(e) {
    e.type !== "configuration" && (L(this, Vi, lo).call(this, e.data), a(this, Tr).decode(new EncodedVideoChunk({
      // Treat `undefined` as `key`, otherwise it won't decode.
      type: e.keyframe === !1 ? "delta" : "key",
      timestamp: 0,
      data: e.data
    })));
  }
}
Tr = new WeakMap(), Yn = new WeakMap(), Vi = new WeakSet(), lo = function(e) {
  const n = new vt(e).searchSequenceHeaderObu();
  if (!n)
    return;
  const { seq_profile: i, seq_level_idx: [s = 0], max_frame_width_minus_1: o, max_frame_height_minus_1: l, color_config: { BitDepth: d, mono_chrome: f, subsampling_x: p, subsampling_y: m, chroma_sample_position: b, color_description_present_flag: h } } = n;
  let y, v, T, S;
  h ? {
    color_primaries: y,
    transfer_characteristics: v,
    matrix_coefficients: T,
    color_range: S
  } = n.color_config : (y = vt.ColorPrimaries.Bt709, v = vt.TransferCharacteristics.Bt709, T = vt.MatrixCoefficients.Bt709, S = !1);
  const z = o + 1, C = l + 1;
  a(this, Yn).call(this, z, C);
  const D = [
    "av01",
    i.toString(16),
    Hr(s) + (n.seq_tier[0] ? "H" : "M"),
    Hr(d),
    f ? "1" : "0",
    (p ? "1" : "0") + (m ? "1" : "0") + b.toString(),
    Hr(y),
    Hr(v),
    Hr(T),
    S ? "1" : "0"
  ].join(".");
  a(this, Tr).configure({
    codec: D,
    optimizeForLatency: !0
  });
};
var tt, Jn;
class uo {
  constructor(e) {
    u(this, tt);
    u(this, Jn);
    c(this, Jn, e);
  }
  decode(e) {
    if (e.type === "configuration") {
      c(this, tt, e.data), this.configure(e.data);
      return;
    }
    let t;
    a(this, tt) !== void 0 ? (t = new Uint8Array(a(this, tt).length + e.data.length), t.set(a(this, tt), 0), t.set(e.data, a(this, tt).length), c(this, tt, void 0)) : t = e.data, a(this, Jn).decode(new EncodedVideoChunk({
      // Treat `undefined` as `key`, otherwise won't decode.
      type: e.keyframe === !1 ? "delta" : "key",
      timestamp: 0,
      data: t
    }));
  }
}
tt = new WeakMap(), Jn = new WeakMap();
var Kn, Qn;
class ld extends uo {
  constructor(t, n) {
    super(t);
    u(this, Kn);
    u(this, Qn);
    c(this, Kn, t), c(this, Qn, n);
  }
  configure(t) {
    const { profileIndex: n, constraintSet: i, levelIndex: s, croppedWidth: o, croppedHeight: l } = Qa(t);
    a(this, Qn).call(this, o, l);
    const d = "avc1." + ns(n) + ns(i) + ns(s);
    a(this, Kn).configure({
      codec: d,
      optimizeForLatency: !0
    });
  }
}
Kn = new WeakMap(), Qn = new WeakMap();
var _n, $n;
class ud extends uo {
  constructor(t, n) {
    super(t);
    u(this, _n);
    u(this, $n);
    c(this, _n, t), c(this, $n, n);
  }
  configure(t) {
    const { generalProfileSpace: n, generalProfileIndex: i, generalProfileCompatibilitySet: s, generalTierFlag: o, generalLevelIndex: l, generalConstraintSet: d, croppedWidth: f, croppedHeight: p } = eo(t);
    a(this, $n).call(this, f, p);
    const m = [
      "hev1",
      ["", "A", "B", "C"][n] + i.toString(),
      la(fi(s, 0)),
      (o ? "H" : "L") + l.toString(),
      ...Array.from(d, la)
    ].join(".");
    a(this, _n).configure({
      codec: m,
      // Microsoft Edge requires explicit size to work
      codedWidth: f,
      codedHeight: p,
      optimizeForLatency: !0
    });
  }
}
_n = new WeakMap(), $n = new WeakMap();
var ei, ji, qi, ti, ri, ni;
class dd {
  constructor(e, t) {
    u(this, ei);
    u(this, ji, new ReadableStream({
      start: (e) => {
        c(this, ei, e);
      },
      pull: (e) => {
        e.enqueue(a(this, ti).call(this));
      }
    }, { highWaterMark: 0 }));
    u(this, qi, a(this, ji).getReader());
    u(this, ti);
    u(this, ri, 0);
    u(this, ni);
    c(this, ti, e), c(this, ni, t);
  }
  async borrow() {
    return (await a(this, qi).read()).value;
  }
  return(e) {
    a(this, ri) < a(this, ni) && (a(this, ei).enqueue(e), c(this, ri, a(this, ri) + 1));
  }
}
ei = new WeakMap(), ji = new WeakMap(), qi = new WeakMap(), ti = new WeakMap(), ri = new WeakMap(), ni = new WeakMap();
var ve, ii;
class fd {
  constructor() {
    u(this, ve);
    u(this, ii);
    typeof OffscreenCanvas < "u" ? c(this, ve, new OffscreenCanvas(1, 1)) : (c(this, ve, document.createElement("canvas")), a(this, ve).width = 1, a(this, ve).height = 1), c(this, ii, a(this, ve).getContext("bitmaprenderer", {
      alpha: !1
    }));
  }
  async capture(e) {
    a(this, ve).width = e.displayWidth, a(this, ve).height = e.displayHeight;
    const t = await createImageBitmap(e);
    return a(this, ii).transferFromImageBitmap(t), a(this, ve) instanceof OffscreenCanvas ? await a(this, ve).convertToBlob({
      type: "image/png"
    }) : new Promise((n, i) => {
      a(this, ve).toBlob((s) => {
        s ? n(s) : i(new Error("Failed to convert canvas to blob"));
      }, "image/png");
    });
  }
}
ve = new WeakMap(), ii = new WeakMap();
const ua = /* @__PURE__ */ new dd(() => new fd(), 4);
var Wt, Ft, si, Er, Sr, Zt, Gt, ai, zr, oi, rt, Ar, Me, Yt, ci, mt, Es, Ss, Jt, li;
class Ns {
  /**
   * Create a new WebCodecs video decoder.
   */
  constructor({ codec: e, renderer: t }) {
    u(this, mt);
    u(this, Wt);
    u(this, Ft);
    u(this, si);
    u(this, Er);
    u(this, Sr);
    u(this, Zt);
    u(this, Gt, 0);
    u(this, ai, 0);
    u(this, zr, 0);
    u(this, oi, new vi());
    u(this, rt);
    u(this, Ar, !1);
    u(this, Me);
    u(this, Yt);
    u(this, ci, 0);
    u(this, Jt, (e, t) => {
      a(this, Zt).setSize(e, t), a(this, oi).fire({ width: e, height: t });
    });
    u(this, li, () => {
      a(this, Gt) > 0 && (c(this, ai, a(this, ai) + 1), c(this, zr, a(this, zr) + (a(this, Gt) - 1)), c(this, Gt, 0)), c(this, ci, requestAnimationFrame(a(this, li)));
    });
    switch (c(this, Wt, e), c(this, Zt, t), c(this, rt, new VideoDecoder({
      output: (n) => {
        var i;
        if ((i = a(this, Yt)) == null || i.close(), c(this, Yt, n.clone()), a(this, Ar)) {
          a(this, Me) && (a(this, Me).close(), c(this, zr, a(this, zr) + 1)), c(this, Me, n);
          return;
        }
        L(this, mt, Ss).call(this, n);
      },
      error: (n) => {
        L(this, mt, Es).call(this, n);
      }
    })), a(this, Wt)) {
      case nt.H264:
        c(this, Ft, new ld(a(this, rt), a(this, Jt)));
        break;
      case nt.H265:
        c(this, Ft, new ud(a(this, rt), a(this, Jt)));
        break;
      case nt.AV1:
        c(this, Ft, new cd(a(this, rt), a(this, Jt)));
        break;
      default:
        throw new Error(`Unsupported codec: ${a(this, Wt)}`);
    }
    c(this, si, new ze({
      start: (n) => {
        a(this, Er) ? n.error(a(this, Er)) : c(this, Sr, n);
      },
      write: (n) => {
        a(this, Ft).decode(n);
      }
    })), a(this, li).call(this);
  }
  static get isSupported() {
    return typeof globalThis.VideoDecoder < "u";
  }
  get codec() {
    return a(this, Wt);
  }
  get writable() {
    return a(this, si);
  }
  get renderer() {
    return a(this, Zt);
  }
  get framesRendered() {
    return a(this, ai);
  }
  get framesSkipped() {
    return a(this, zr);
  }
  get sizeChanged() {
    return a(this, oi).event;
  }
  async snapshot() {
    const e = a(this, Yt);
    if (!e)
      return;
    const t = await ua.borrow(), n = await t.capture(e);
    return ua.return(t), n;
  }
  dispose() {
    var e, t;
    cancelAnimationFrame(a(this, ci)), a(this, rt).state !== "closed" && a(this, rt).close(), (e = a(this, Me)) == null || e.close(), (t = a(this, Yt)) == null || t.close();
  }
}
Wt = new WeakMap(), Ft = new WeakMap(), si = new WeakMap(), Er = new WeakMap(), Sr = new WeakMap(), Zt = new WeakMap(), Gt = new WeakMap(), ai = new WeakMap(), zr = new WeakMap(), oi = new WeakMap(), rt = new WeakMap(), Ar = new WeakMap(), Me = new WeakMap(), Yt = new WeakMap(), ci = new WeakMap(), mt = new WeakSet(), Es = function(e) {
  if (a(this, Sr))
    try {
      a(this, Sr).error(e);
    } catch {
    }
  else
    c(this, Er, e);
}, Ss = async function(e) {
  try {
    if (c(this, Ar, !0), a(this, Jt).call(this, e.displayWidth, e.displayHeight), await a(this, Zt).draw(e), c(this, Gt, a(this, Gt) + 1), e.close(), a(this, Me)) {
      const t = a(this, Me);
      c(this, Me, void 0), await L(this, mt, Ss).call(this, t);
    }
    c(this, Ar, !1);
  } catch (t) {
    L(this, mt, Es).call(this, t);
  }
}, Jt = new WeakMap(), li = new WeakMap(), E(Ns, "capabilities", {
  h264: {},
  h265: {},
  av1: {}
});
var fo = { exports: {} };
(function() {
  function r(e, t) {
    throw new Error("abstract");
  }
  r.prototype.drawFrame = function(e) {
    throw new Error("abstract");
  }, r.prototype.clear = function() {
    throw new Error("abstract");
  }, fo.exports = r;
})();
var ho = fo.exports, po = { exports: {} }, mo = { exports: {} };
(function() {
  /**
   * Convert a ratio into a bit-shift count; for instance a ratio of 2
   * becomes a bit-shift of 1, while a ratio of 1 is a bit-shift of 0.
   *
   * @author Brooke Vibber <bvibber@pobox.com>
   * @copyright 2016-2024
   * @license MIT-style
   *
   * @param {number} ratio - the integer ratio to convert.
   * @returns {number} - number of bits to shift to multiply/divide by the ratio.
   * @throws exception if given a non-power-of-two
   */
  function r(e) {
    for (var t = 0, n = e >> 1; n != 0; )
      n = n >> 1, t++;
    if (e !== 1 << t)
      throw "chroma plane dimensions must be power of 2 ratio to luma plane dimensions; got " + e;
    return t;
  }
  mo.exports = r;
})();
var hd = mo.exports;
(function() {
  var r = hd;
  /**
   * Basic YCbCr->RGB conversion
   *
   * @author Brooke Vibber <bvibber@pobox.com>
   * @copyright 2014-2024
   * @license MIT-style
   *
   * @param {YUVFrame} buffer - input frame buffer
   * @param {Uint8ClampedArray} output - array to draw RGBA into
   * Assumes that the output array already has alpha channel set to opaque.
   */
  function e(t, n) {
    var i = t.format.width | 0, s = t.format.height | 0, o = r(t.format.width / t.format.chromaWidth) | 0, l = r(t.format.height / t.format.chromaHeight) | 0, d = t.y.bytes, f = t.u.bytes, p = t.v.bytes, m = t.y.stride | 0, b = t.u.stride | 0, h = t.v.stride | 0, y = i << 2, v = 0, T = 0, S = 0, z = 0, C = 0, D = 0, k = 0, H = 0, R = 0, I = 0, w = 0, N = 0, x = 0, _ = 0, F = 0, P = 0, A = 0, X = 0;
    if (o == 1 && l == 1)
      for (k = 0, H = y, X = 0, P = 0; P < s; P += 2) {
        for (T = P * m | 0, S = T + m | 0, z = X * b | 0, C = X * h | 0, F = 0; F < i; F += 2)
          R = f[z++] | 0, I = p[C++] | 0, N = (409 * I | 0) - 57088 | 0, x = (100 * R | 0) + (208 * I | 0) - 34816 | 0, _ = (516 * R | 0) - 70912 | 0, w = 298 * d[T++] | 0, n[k] = w + N >> 8, n[k + 1] = w - x >> 8, n[k + 2] = w + _ >> 8, k += 4, w = 298 * d[T++] | 0, n[k] = w + N >> 8, n[k + 1] = w - x >> 8, n[k + 2] = w + _ >> 8, k += 4, w = 298 * d[S++] | 0, n[H] = w + N >> 8, n[H + 1] = w - x >> 8, n[H + 2] = w + _ >> 8, H += 4, w = 298 * d[S++] | 0, n[H] = w + N >> 8, n[H + 1] = w - x >> 8, n[H + 2] = w + _ >> 8, H += 4;
        k += y, H += y, X++;
      }
    else
      for (D = 0, P = 0; P < s; P++)
        for (A = 0, X = P >> l, v = P * m | 0, z = X * b | 0, C = X * h | 0, F = 0; F < i; F++)
          A = F >> o, R = f[z + A] | 0, I = p[C + A] | 0, N = (409 * I | 0) - 57088 | 0, x = (100 * R | 0) + (208 * I | 0) - 34816 | 0, _ = (516 * R | 0) - 70912 | 0, w = 298 * d[v++] | 0, n[D] = w + N >> 8, n[D + 1] = w - x >> 8, n[D + 2] = w + _ >> 8, D += 4;
  }
  po.exports = {
    convertYCbCr: e
  };
})();
var pd = po.exports;
(function() {
  var r = ho, e = pd;
  function t(n) {
    var i = this, s = n.getContext("2d"), o = null, l = null, d = null;
    function f(m, b) {
      o = s.createImageData(m, b);
      for (var h = o.data, y = m * b * 4, v = 0; v < y; v += 4)
        h[v + 3] = 255;
    }
    function p(m, b) {
      l = document.createElement("canvas"), l.width = m, l.height = b, d = l.getContext("2d");
    }
    return i.drawFrame = function(b) {
      var h = b.format;
      (n.width !== h.displayWidth || n.height !== h.displayHeight) && (n.width = h.displayWidth, n.height = h.displayHeight), (o === null || o.width != h.width || o.height != h.height) && f(h.width, h.height), e.convertYCbCr(b, o.data);
      var y = h.cropWidth != h.displayWidth || h.cropHeight != h.displayHeight, v;
      y ? (l || p(h.cropWidth, h.cropHeight), v = d) : v = s, v.putImageData(
        o,
        -h.cropLeft,
        -h.cropTop,
        // must offset the offset
        h.cropLeft,
        h.cropTop,
        h.cropWidth,
        h.cropHeight
      ), y && s.drawImage(l, 0, 0, h.displayWidth, h.displayHeight);
    }, i.clear = function() {
      s.clearRect(0, 0, n.width, n.height);
    }, i;
  }
  t.prototype = Object.create(r.prototype);
})();
var md = {
  vertex: `precision mediump float;

attribute vec2 aPosition;
attribute vec2 aLumaPosition;
attribute vec2 aChromaPosition;
varying vec2 vLumaPosition;
varying vec2 vChromaPosition;
void main() {
    gl_Position = vec4(aPosition, 0, 1);
    vLumaPosition = aLumaPosition;
    vChromaPosition = aChromaPosition;
}
`,
  fragment: `// inspired by https://github.com/mbebenita/Broadway/blob/master/Player/canvas.js

precision mediump float;

uniform sampler2D uTextureY;
uniform sampler2D uTextureCb;
uniform sampler2D uTextureCr;
varying vec2 vLumaPosition;
varying vec2 vChromaPosition;
void main() {
   // Y, Cb, and Cr planes are uploaded as ALPHA textures.
   float fY = texture2D(uTextureY, vLumaPosition).w;
   float fCb = texture2D(uTextureCb, vChromaPosition).w;
   float fCr = texture2D(uTextureCr, vChromaPosition).w;

   // Premultipy the Y...
   float fYmul = fY * 1.1643828125;

   // And convert that to RGB!
   gl_FragColor = vec4(
     fYmul + 1.59602734375 * fCr - 0.87078515625,
     fYmul - 0.39176171875 * fCb - 0.81296875 * fCr + 0.52959375,
     fYmul + 2.017234375   * fCb - 1.081390625,
     1
   );
}
`,
  vertexStripe: `precision mediump float;

attribute vec2 aPosition;
attribute vec2 aTexturePosition;
varying vec2 vTexturePosition;

void main() {
    gl_Position = vec4(aPosition, 0, 1);
    vTexturePosition = aTexturePosition;
}
`,
  fragmentStripe: `// extra 'stripe' texture fiddling to work around IE 11's poor performance on gl.LUMINANCE and gl.ALPHA textures

precision mediump float;

uniform sampler2D uStripe;
uniform sampler2D uTexture;
varying vec2 vTexturePosition;
void main() {
   // Y, Cb, and Cr planes are mapped into a pseudo-RGBA texture
   // so we can upload them without expanding the bytes on IE 11
   // which doesn't allow LUMINANCE or ALPHA textures
   // The stripe textures mark which channel to keep for each pixel.
   // Each texture extraction will contain the relevant value in one
   // channel only.

   float fLuminance = dot(
      texture2D(uStripe, vTexturePosition),
      texture2D(uTexture, vTexturePosition)
   );

   gl_FragColor = vec4(0, 0, 0, fLuminance);
}
`
};
(function() {
  var r = ho, e = md;
  function t(n) {
    var i = this, s = t.contextForCanvas(n);
    if (s === null)
      throw new Error("WebGL unavailable");
    function o(P, A) {
      var X = s.createShader(P);
      if (s.shaderSource(X, A), s.compileShader(X), !s.getShaderParameter(X, s.COMPILE_STATUS)) {
        var V = s.getShaderInfoLog(X);
        throw s.deleteShader(X), new Error("GL shader compilation for " + P + " failed: " + V);
      }
      return X;
    }
    var l, d, f = new Float32Array([
      // First triangle (top left, clockwise)
      -1,
      -1,
      1,
      -1,
      -1,
      1,
      // Second triangle (bottom right, clockwise)
      -1,
      1,
      1,
      -1,
      1,
      1
    ]), p = {}, m = {}, b = {}, h, y, v, T, S, z, C, D, k, H;
    function R(P, A) {
      return (!p[P] || A) && (p[P] = s.createTexture()), p[P];
    }
    function I(P, A, X, V, q) {
      var $ = !p[P] || A, ne = R(P, A);
      if (s.activeTexture(s.TEXTURE0), t.stripe) {
        var ee = !p[P + "_temp"] || A, le = R(P + "_temp", A);
        s.bindTexture(s.TEXTURE_2D, le), ee ? (s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_S, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_T, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MIN_FILTER, s.NEAREST), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MAG_FILTER, s.NEAREST), s.texImage2D(
          s.TEXTURE_2D,
          0,
          // mip level
          s.RGBA,
          // internal format
          X / 4,
          V,
          0,
          // border
          s.RGBA,
          // format
          s.UNSIGNED_BYTE,
          // type
          q
          // data!
        )) : s.texSubImage2D(
          s.TEXTURE_2D,
          0,
          // mip level
          0,
          // x offset
          0,
          // y offset
          X / 4,
          V,
          s.RGBA,
          // format
          s.UNSIGNED_BYTE,
          // type
          q
          // data!
        );
        var ie = p[P + "_stripe"], se = !ie || A;
        se && (ie = R(P + "_stripe", A)), s.bindTexture(s.TEXTURE_2D, ie), se && (s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_S, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_T, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MIN_FILTER, s.NEAREST), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MAG_FILTER, s.NEAREST), s.texImage2D(
          s.TEXTURE_2D,
          0,
          // mip level
          s.RGBA,
          // internal format
          X,
          1,
          0,
          // border
          s.RGBA,
          // format
          s.UNSIGNED_BYTE,
          //type
          x(X)
          // data!
        ));
      } else
        s.bindTexture(s.TEXTURE_2D, ne), $ ? (s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_S, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_T, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MIN_FILTER, s.LINEAR), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MAG_FILTER, s.LINEAR), s.texImage2D(
          s.TEXTURE_2D,
          0,
          // mip level
          s.ALPHA,
          // internal format
          X,
          V,
          0,
          // border
          s.ALPHA,
          // format
          s.UNSIGNED_BYTE,
          //type
          q
          // data!
        )) : s.texSubImage2D(
          s.TEXTURE_2D,
          0,
          // mip level
          0,
          // x
          0,
          // y
          X,
          V,
          s.ALPHA,
          // internal format
          s.UNSIGNED_BYTE,
          //type
          q
          // data!
        );
    }
    function w(P, A, X, V) {
      var q = p[P];
      s.useProgram(d);
      var $ = m[P];
      (!$ || A) && (s.activeTexture(s.TEXTURE0), s.bindTexture(s.TEXTURE_2D, q), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_S, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_T, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MIN_FILTER, s.LINEAR), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MAG_FILTER, s.LINEAR), s.texImage2D(
        s.TEXTURE_2D,
        0,
        // mip level
        s.RGBA,
        // internal format
        X,
        V,
        0,
        // border
        s.RGBA,
        // format
        s.UNSIGNED_BYTE,
        //type
        null
        // data!
      ), $ = m[P] = s.createFramebuffer()), s.bindFramebuffer(s.FRAMEBUFFER, $), s.framebufferTexture2D(s.FRAMEBUFFER, s.COLOR_ATTACHMENT0, s.TEXTURE_2D, q, 0);
      var ne = p[P + "_temp"];
      s.activeTexture(s.TEXTURE1), s.bindTexture(s.TEXTURE_2D, ne), s.uniform1i(z, 1);
      var ee = p[P + "_stripe"];
      s.activeTexture(s.TEXTURE2), s.bindTexture(s.TEXTURE_2D, ee), s.uniform1i(S, 2), s.bindBuffer(s.ARRAY_BUFFER, h), s.enableVertexAttribArray(y), s.vertexAttribPointer(y, 2, s.FLOAT, !1, 0, 0), s.bindBuffer(s.ARRAY_BUFFER, v), s.enableVertexAttribArray(T), s.vertexAttribPointer(T, 2, s.FLOAT, !1, 0, 0), s.viewport(0, 0, X, V), s.drawArrays(s.TRIANGLES, 0, f.length / 2), s.bindFramebuffer(s.FRAMEBUFFER, null);
    }
    function N(P, A, X) {
      s.activeTexture(A), s.bindTexture(s.TEXTURE_2D, p[P]), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_S, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_WRAP_T, s.CLAMP_TO_EDGE), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MIN_FILTER, s.LINEAR), s.texParameteri(s.TEXTURE_2D, s.TEXTURE_MAG_FILTER, s.LINEAR), s.uniform1i(s.getUniformLocation(l, P), X);
    }
    function x(P) {
      if (b[P])
        return b[P];
      for (var A = P, X = new Uint32Array(A), V = 0; V < A; V += 4)
        X[V] = 255, X[V + 1] = 65280, X[V + 2] = 16711680, X[V + 3] = 4278190080;
      return b[P] = new Uint8Array(X.buffer);
    }
    function _(P, A) {
      var X = o(s.VERTEX_SHADER, P), V = o(s.FRAGMENT_SHADER, A), q = s.createProgram();
      if (s.attachShader(q, X), s.attachShader(q, V), s.linkProgram(q), !s.getProgramParameter(q, s.LINK_STATUS)) {
        var $ = s.getProgramInfoLog(q);
        throw s.deleteProgram(q), new Error("GL program linking failed: " + $);
      }
      return q;
    }
    function F() {
      if (t.stripe) {
        d = _(e.vertexStripe, e.fragmentStripe), s.getAttribLocation(d, "aPosition"), v = s.createBuffer();
        var P = new Float32Array([
          0,
          0,
          1,
          0,
          0,
          1,
          0,
          1,
          1,
          0,
          1,
          1
        ]);
        s.bindBuffer(s.ARRAY_BUFFER, v), s.bufferData(s.ARRAY_BUFFER, P, s.STATIC_DRAW), T = s.getAttribLocation(d, "aTexturePosition"), S = s.getUniformLocation(d, "uStripe"), z = s.getUniformLocation(d, "uTexture");
      }
      l = _(e.vertex, e.fragment), h = s.createBuffer(), s.bindBuffer(s.ARRAY_BUFFER, h), s.bufferData(s.ARRAY_BUFFER, f, s.STATIC_DRAW), y = s.getAttribLocation(l, "aPosition"), C = s.createBuffer(), D = s.getAttribLocation(l, "aLumaPosition"), k = s.createBuffer(), H = s.getAttribLocation(l, "aChromaPosition");
    }
    return i.drawFrame = function(P) {
      var A = P.format, X = !l || n.width !== A.displayWidth || n.height !== A.displayHeight;
      if (X && (n.width = A.displayWidth, n.height = A.displayHeight, i.clear()), l || F(), X) {
        var V = function(q, $, ne) {
          var ee = A.cropLeft / ne, le = (A.cropLeft + A.cropWidth) / ne, ie = (A.cropTop + A.cropHeight) / A.height, se = A.cropTop / A.height, He = new Float32Array([
            ee,
            ie,
            le,
            ie,
            ee,
            se,
            ee,
            se,
            le,
            ie,
            le,
            se
          ]);
          s.bindBuffer(s.ARRAY_BUFFER, q), s.bufferData(s.ARRAY_BUFFER, He, s.STATIC_DRAW);
        };
        V(
          C,
          D,
          P.y.stride
        ), V(
          k,
          H,
          P.u.stride * A.width / A.chromaWidth
        );
      }
      I("uTextureY", X, P.y.stride, A.height, P.y.bytes), I("uTextureCb", X, P.u.stride, A.chromaHeight, P.u.bytes), I("uTextureCr", X, P.v.stride, A.chromaHeight, P.v.bytes), t.stripe && (w("uTextureY", X, P.y.stride, A.height), w("uTextureCb", X, P.u.stride, A.chromaHeight), w("uTextureCr", X, P.v.stride, A.chromaHeight)), s.useProgram(l), s.viewport(0, 0, n.width, n.height), N("uTextureY", s.TEXTURE0, 0), N("uTextureCb", s.TEXTURE1, 1), N("uTextureCr", s.TEXTURE2, 2), s.bindBuffer(s.ARRAY_BUFFER, h), s.enableVertexAttribArray(y), s.vertexAttribPointer(y, 2, s.FLOAT, !1, 0, 0), s.bindBuffer(s.ARRAY_BUFFER, C), s.enableVertexAttribArray(D), s.vertexAttribPointer(D, 2, s.FLOAT, !1, 0, 0), s.bindBuffer(s.ARRAY_BUFFER, k), s.enableVertexAttribArray(H), s.vertexAttribPointer(H, 2, s.FLOAT, !1, 0, 0), s.drawArrays(s.TRIANGLES, 0, f.length / 2);
    }, i.clear = function() {
      s.viewport(0, 0, n.width, n.height), s.clearColor(0, 0, 0, 0), s.clear(s.COLOR_BUFFER_BIT);
    }, i.clear(), i;
  }
  t.stripe = !1, t.contextForCanvas = function(n) {
    var i = {
      // Don't trigger discrete GPU in multi-GPU systems
      preferLowPowerToHighPerformance: !0,
      powerPreference: "low-power",
      // Don't try to use software GL rendering!
      failIfMajorPerformanceCaveat: !0,
      // In case we need to capture the resulting output.
      preserveDrawingBuffer: !0
    };
    return n.getContext("webgl", i) || n.getContext("experimental-webgl", i);
  }, t.isAvailable = function() {
    var n = document.createElement("canvas"), i;
    n.width = 1, n.height = 1;
    try {
      i = t.contextForCanvas(n);
    } catch {
      return !1;
    }
    if (i) {
      var s = i.TEXTURE0, o = 4, l = 4, d = i.createTexture(), f = new Uint8Array(o * l), p = t.stripe ? o / 4 : o, m = t.stripe ? i.RGBA : i.ALPHA, b = t.stripe ? i.NEAREST : i.LINEAR;
      i.activeTexture(s), i.bindTexture(i.TEXTURE_2D, d), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_WRAP_S, i.CLAMP_TO_EDGE), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_WRAP_T, i.CLAMP_TO_EDGE), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_MIN_FILTER, b), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_MAG_FILTER, b), i.texImage2D(
        i.TEXTURE_2D,
        0,
        // mip level
        m,
        // internal format
        p,
        l,
        0,
        // border
        m,
        // format
        i.UNSIGNED_BYTE,
        //type
        f
        // data!
      );
      var h = i.getError();
      return !h;
    } else
      return !1;
  }, t.prototype = Object.create(r.prototype);
})();
function yo() {
  if (typeof document < "u")
    return document.createElement("canvas");
  if (typeof OffscreenCanvas < "u")
    return new OffscreenCanvas(1, 1);
  throw new Error("no canvas input found nor any canvas can be created");
}
var Ve;
class bo {
  constructor(e) {
    u(this, Ve);
    e ? c(this, Ve, e) : c(this, Ve, yo());
  }
  get canvas() {
    return a(this, Ve);
  }
  setSize(e, t) {
    (a(this, Ve).width !== e || a(this, Ve).height !== t) && (a(this, Ve).width = e, a(this, Ve).height = t);
  }
}
Ve = new WeakMap();
var ui;
class yd extends bo {
  constructor(t) {
    super(t);
    u(this, ui);
    c(this, ui, this.canvas.getContext("bitmaprenderer", {
      alpha: !1
    }));
  }
  async draw(t) {
    const n = await createImageBitmap(t);
    a(this, ui).transferFromImageBitmap(n);
  }
}
ui = new WeakMap();
const bd = Promise.resolve();
function da(r, e) {
  const t = {
    // Low-power GPU should be enough for video rendering.
    powerPreference: "low-power",
    alpha: !1,
    // Disallow software rendering.
    // Other rendering methods are faster than software-based WebGL.
    failIfMajorPerformanceCaveat: !0,
    preserveDrawingBuffer: !!e
  };
  return r.getContext("webgl2", t) || r.getContext("webgl", t);
}
var di;
const tr = class tr extends bo {
  /**
   * Create a new WebGL frame renderer.
   * @param canvas The canvas to render frames to.
   * @param enableCapture
   * Whether to allow capturing the canvas content using APIs like `readPixels` and `toDataURL`.
   * Enable this option may reduce performance.
   */
  constructor(t, n) {
    super(t);
    u(this, di);
    const i = da(this.canvas, n);
    if (!i)
      throw new Error("WebGL not supported");
    c(this, di, i);
    const s = i.createShader(i.VERTEX_SHADER);
    if (i.shaderSource(s, tr.vertexShaderSource), i.compileShader(s), !i.getShaderParameter(s, i.COMPILE_STATUS))
      throw new Error(i.getShaderInfoLog(s));
    const o = i.createShader(i.FRAGMENT_SHADER);
    if (i.shaderSource(o, tr.fragmentShaderSource), i.compileShader(o), !i.getShaderParameter(o, i.COMPILE_STATUS))
      throw new Error(i.getShaderInfoLog(o));
    const l = i.createProgram();
    if (i.attachShader(l, s), i.attachShader(l, o), i.linkProgram(l), !i.getProgramParameter(l, i.LINK_STATUS))
      throw new Error(i.getProgramInfoLog(l));
    i.useProgram(l);
    const d = i.createBuffer();
    i.bindBuffer(i.ARRAY_BUFFER, d), i.bufferData(i.ARRAY_BUFFER, new Float32Array([-1, -1, -1, 1, 1, 1, 1, -1]), i.STATIC_DRAW);
    const f = i.getAttribLocation(l, "xy");
    i.vertexAttribPointer(f, 2, i.FLOAT, !1, 0, 0), i.enableVertexAttribArray(f);
    const p = i.createTexture();
    i.bindTexture(i.TEXTURE_2D, p), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_MAG_FILTER, i.NEAREST), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_MIN_FILTER, i.NEAREST), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_WRAP_S, i.CLAMP_TO_EDGE), i.texParameteri(i.TEXTURE_2D, i.TEXTURE_WRAP_T, i.CLAMP_TO_EDGE);
  }
  static get isSupported() {
    const t = yo();
    return !!da(t);
  }
  draw(t) {
    const n = a(this, di);
    return n.texImage2D(n.TEXTURE_2D, 0, n.RGBA, n.RGBA, n.UNSIGNED_BYTE, t), n.viewport(0, 0, n.drawingBufferWidth, n.drawingBufferHeight), n.drawArrays(n.TRIANGLE_FAN, 0, 4), bd;
  }
};
di = new WeakMap(), E(tr, "vertexShaderSource", `
        attribute vec2 xy;

        varying highp vec2 uv;

        void main(void) {
            gl_Position = vec4(xy, 0.0, 1.0);
            // Map vertex coordinates (-1 to +1) to UV coordinates (0 to 1).
            // UV coordinates are Y-flipped relative to vertex coordinates.
            uv = vec2((1.0 + xy.x) / 2.0, (1.0 - xy.y) / 2.0);
        }
`), E(tr, "fragmentShaderSource", `
        varying highp vec2 uv;

        uniform sampler2D texture;

        void main(void) {
            gl_FragColor = texture2D(texture, uv);
        }
`);
let Ri = tr;
const fa = "/data/local/tmp/scrcpy-server-nutcracker.jar";
function wo() {
  return typeof navigator < "u" && "usb" in navigator && !!Or.BROWSER && Ns.isSupported;
}
let is = null;
function wd() {
  return is || (is = new bl("nutcracker-dashboard")), is;
}
let Mr = null;
function Ed() {
  return Mr !== null;
}
function vo(r) {
  return /already in used|already open|access denied|in use/i.test(r);
}
function zs(r) {
  return vo(r) ? `Error: el dispositivo ya está reclamado por otro programa (adb). Corré "adb kill-server" y reintentá. (${r})` : `Error conectando por WebUSB: ${r}`;
}
const vd = (r) => new Promise((e) => setTimeout(e, r));
async function Sd(r, e) {
  try {
    if (!wo())
      return e("WebUSB no soportado en este navegador (usa Chrome/Edge/Opera)."), null;
    e("Solicitando acceso al dispositivo por USB…");
    const t = await Or.BROWSER.requestDevice();
    return t ? (await xo(t, r, e), t.serial) : (e("Ningún dispositivo seleccionado."), null);
  } catch (t) {
    const n = t instanceof Error ? t.message : String(t);
    return e(zs(n)), console.error("[nutcracker webusb] connect() falló:", t), null;
  }
}
async function zd(r, e, t, n = 3) {
  try {
    if (!wo()) return null;
    const i = await Or.BROWSER.getDevices();
    if (i.length === 0) return null;
    const s = t && i.find((o) => o.serial === t) || i[0];
    for (let o = 0; o < n; o++)
      try {
        return e(
          o === 0 ? "Reconectando por USB tras recargar la página…" : `Reconectando por USB (intento ${o + 1}/${n})…`
        ), await xo(s, r, e), s.serial;
      } catch (l) {
        const d = l instanceof Error ? l.message : String(l);
        if (o === n - 1 || !vo(d))
          return e(zs(d)), console.error("[nutcracker webusb] reconnect() falló:", l), null;
        await vd(600);
      }
    return null;
  } catch (i) {
    const s = i instanceof Error ? i.message : String(i);
    return e(zs(s)), console.error("[nutcracker webusb] reconnect() falló:", i), null;
  }
}
async function xd(r) {
  const e = Mr;
  if (Mr = null, !!e) {
    e.abort.abort();
    try {
      e.decoder.dispose();
    } catch (t) {
      console.warn("[nutcracker webusb] decoder.dispose() falló:", t);
    }
    try {
      await e.client.close();
    } catch (t) {
      console.warn("[nutcracker webusb] client.close() falló:", t);
    }
    try {
      await e.adb.close();
    } catch (t) {
      console.warn("[nutcracker webusb] adb.close() falló:", t);
    }
    r == null || r("Desconectado — el cable USB queda libre para adb.");
  }
}
async function xo(r, e, t) {
  await xd(), t("Conectando…");
  const n = await r.connect();
  t("Autenticando (revisa el teléfono si pide autorizar)…");
  const i = await xs.authenticate({
    serial: r.serial,
    connection: n,
    credentialStore: wd()
  }), s = new Gc(i);
  t("Descargando/enviando scrcpy-server al dispositivo…");
  const o = await fetch(od).then((T) => T.arrayBuffer());
  await Qt.pushServer(
    s,
    new yt({
      start(T) {
        T.enqueue(new Uint8Array(o)), T.close();
      }
    }),
    fa
  ), t("Arrancando scrcpy en el dispositivo…");
  const l = new sd(
    new $u(
      {
        video: !0,
        audio: !1,
        control: !1
        // solo video en esta primera versión, sin control táctil
      },
      ad
    )
  ), d = await Qt.start(s, fa, l), f = d.videoStream;
  if (!f) {
    t("El servidor no devolvió stream de video (¿deshabilitado en options?)."), await s.close();
    return;
  }
  const { stream: p, metadata: m } = await f, b = Ri.isSupported;
  t(b ? "Iniciando decodificación (WebGL)…" : "Iniciando decodificación (canvas 2D, sin WebGL)…");
  const h = b ? new Ri(e) : new yd(e), y = new Ns({ codec: m.codec, renderer: h }), v = new AbortController();
  Mr = { adb: s, client: d, decoder: y, abort: v }, p.pipeTo(y.writable, { signal: v.signal }).catch((T) => {
    v.signal.aborted || (Mr = null, t(`Stream de video terminó: ${String(T)}`));
  }), t("● USB directo (fluido) — conectado");
}
export {
  Sd as connect,
  xd as disconnect,
  Ed as isConnected,
  wo as isSupported,
  zd as reconnect
};

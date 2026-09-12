export const {TlsClient} = (() => {
    const m = new TextEncoder, L = new Uint8Array, u = (...n) => {
            const r = [], e = i => i.forEach(x => x instanceof Uint8Array ? r.push(...x) : Array.isArray(x) ? e(x) : r.push(x));
            return e(n), new Uint8Array(r)
        }, f = n => [n >> 8, n & 255], _ = (n, t) => n[t] << 8 | n[t + 1], b = (...n) => {
            const s = new Uint8Array(n.reduce((r, c) => r + (c?.length || 0), 0));
            let e = 0;
            for (const i of n) i?.length && (s.set(i, e), e += i.length);
            return s
        }, j = n => n === "SHA-384" ? 48 : 32, D = n => n?.[0] === 1 && n[1] === 112, B = async (n, t, s) => new Uint8Array(await crypto.subtle.sign("HMAC", t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]), s)), M = async (n, t) => new Uint8Array(await crypto.subtle.digest(n, t)), W = (n, t) => crypto.subtle.importKey("raw", n, {name: "AES-GCM"}, !1, [t]),
        R = async (n, t, s, h) => new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv: t, additionalData: h}, n, s)), N = async (n, t, s, h) => new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: t, additionalData: h}, n, s)), v = (n, t, s = 771) => {
            const h = new Uint8Array(5 + t.length);
            return h.set([n, s >> 8, s, t.length >> 8, t.length]), h.set(t, 5), h
        }, K = (n, t) => {
            const s = new Uint8Array(4 + t.length), l = t.length;
            return s.set([n, l >> 16, l >> 8, l]), s.set(t, 4), s
        };
    async function G(n, t, s, h, e = "SHA-256") {
        const i = b(m.encode(t), s), l = n.type ? n : await crypto.subtle.importKey("raw", n, {name: "HMAC", hash: e}, !1, ["sign"]);
        let r = new Uint8Array(0), c = i;
        for (; r.length < h;) c = await B(e, l, c), r = b(r, await B(e, l, b(c, i)));
        return r.slice(0, h)
    }
    const V = (n, t, s) => B(n, t?.length ? t : new Uint8Array(j(n)), s);
    async function q(n, t, s, h, e) {
        const i = typeof s == "string" ? m.encode("tls13 " + s) : s, r = j(n), l = u(f(e), i.length, i, h.length, h), p = t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]);
        let a = new Uint8Array(0), w = new Uint8Array(0);
        for (let y = 1; y <= Math.ceil(e / r); y++) w = await B(n, p, b(w, l, [y])), a = b(a, w);
        return a.slice(0, e)
    }
    const Z = async (n = "P-256") => {
        const x = n === "X25519", s = await crypto.subtle.generateKey(x ? {name: n} : {name: "ECDH", namedCurve: n}, !0, ["deriveBits"]);
        return {kp: s, pk: new Uint8Array(await crypto.subtle.exportKey("raw", s.publicKey))}
    }, $ = async (n, t, s = "P-256") => {
        const x = s === "X25519", h = await crypto.subtle.importKey("raw", t, x ? {name: s} : {name: "ECDH", namedCurve: s}, !1, []);
        return new Uint8Array(await crypto.subtle.deriveBits({name: x ? s : "ECDH", public: h}, n, 256))
    };
    class P {
        constructor(n) {this.b = new Uint8Array(n), this.h = this.t = 0}
        feed(t) {
            if (this.t + t.length > this.b.length) {
                const s = this.t - this.h, m2 = s + t.length > this.b.length, e = m2 ? new Uint8Array(Math.max(this.b.length * 2, s + t.length)) : this.b;
                m2 ? e.set(this.b.subarray(this.h, this.t)) : e.copyWithin(0, this.h, this.t), this.b = e, this.t = s, this.h = 0
            }
            this.b.set(t, this.t), this.t += t.length
        }
    }
    class rt extends P {
        constructor() {super(32768)}
        next() {
            if (this.t - this.h < 5) return null;
            const t = this.b[this.h], s = _(this.b, this.h + 1), h = _(this.b, this.h + 3);
            if (h > 18432) throw new Error;
            if (this.t - this.h < 5 + h) return null;
            const e = this.b.subarray(this.h + 5, this.h += 5 + h);
            return this.h === this.t && (this.h = this.t = 0), {type: t, version: s, length: h, fragment: e}
        }
    }
    class at extends P {
        constructor() {super(4096)}
        next() {
            if (this.t - this.h < 4) return null;
            const t = this.b[this.h], s = this.b[this.h + 1] << 16 | _(this.b, this.h + 2);
            if (this.t - this.h < 4 + s) return null;
            const body = this.b.subarray(this.h + 4, this.h + 4 + s), raw = this.b.subarray(this.h, this.h += 4 + s);
            return this.h === this.t && (this.h = this.t = 0), {type: t, length: s, body: body, raw: raw}
        }
    }
    function ct(n, t, s, {sessionId: h = L} = {}) {
        const i = u(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(f)), r = [u(255, 1, 0, 1, 0)];
        if (t) {
            const p = m.encode(t);
            r.push(u(0, 0, f(p.length + 5), f(p.length + 3), 0, f(p.length), p))
        }
        const a = b(u(0, 29, f(s.x25519.length), s.x25519), u(0, 23, f(s.p256.length), s.p256));
        r.push(u(f(11), 0, 2, 1, 0), u(f(10), 0, 6, 0, 4, 0, 29, 0, 23), u(f(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(f)), u(f(43), 0, 5, 4, 3, 4, 3, 3), u(f(45), 0, 2, 1, 1), u(f(51), f(a.length + 2), f(a.length), a));
        const w = b(...r);
        return K(1, u(f(771), n, h.length, h, f(i.length), i, 1, 0, f(w.length), w))
    }
    const T = async (n, t, s, h, e) => {
        const i = t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: n}, !1, ["sign"]), [r, c] = await Promise.all([q(n, i, "key", L, s), q(n, i, "iv", L, h)]);
        return [await W(r, e), c]
    }, Q = n => {
        let t = n.length - 1;
        for (; t >= 0 && !n[t];) t--;
        if (t < 0) throw new Error;
        return {data: n.subarray(0, t), type: n[t]}
    }, I = (n, t) => {
        const s = n.slice();
        for (let h = 0; h < 8; h++) s[s.length - 1 - h] ^= Number(t >> BigInt(h << 3) & 0xffn);
        return s
    };
    class lt {
        constructor(t, s = {}) {this.sk = t, this.sn = s.serverName || "", this.cr = crypto.getRandomValues(new Uint8Array(32)), this.id = crypto.getRandomValues(new Uint8Array(32)), this.sr = this.ms = this.hs = this.ck = this.wk = this.cv = this.wv = this.ch = this.sh = this.ci = this.si = this.ak = this.bk = this.ai = this.bi = this.cp = this.rd = this.wr = this.cs = this.cc = null, this.hb = new Uint8Array(8192), this.hl = 0, this.hc = this.i3 = this.cl = this.cg = this.fl = !1, this.cn = this.qn = 0n, this.rp = new rt, this.hp = new at, this.kp = new Map, this.pq = [], this.wq = Promise.resolve(), this.rb = new Uint8Array(65536)}
        rh(t) {
            if (this.hl + t.length > this.hb.length) {
                const s = new Uint8Array(Math.max(this.hb.length * 2, this.hl + t.length));
                s.set(this.hb.subarray(0, this.hl)), this.hb = s
            }
            this.hb.set(t, this.hl), this.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {this.fl = this.cl = !0, this.sk?.close()}
        async rc() {
            const t = await this.rd.read(this.rb);
            if (!t) throw new Error;
            return !t.done && t.value && (this.rb = new Uint8Array(t.value.buffer)), t
        }
        async pr(t) {
            for (; ;) {
                for (let s; s = this.rp.next();) if (await t(s)) return;
                const {value: h, done: e} = await this.rc();
                if (e) throw new Error;
                this.rp.feed(h)
            }
        }
        async handshake() {
            const [t, s] = await Promise.all([Z("P-256"), Z("X25519")]);
            this.kp = new Map([[23, t], [29, s]]), this.rd = this.sk.readable.getReader({mode: "byob"}), this.wr = this.sk.writable.getWriter();
            try {
                const h = {p256: t.pk, x25519: s.pk}, e = ct(this.cr, this.sn, h, {sessionId: this.id});
                this.rh(e), await this.wr.write(v(22, e, 769));
                const i = await this.rsh();
                if (i.isTls13) {
                    const c = i.ks?.group === 29 ? "X25519" : i.ks?.group === 23 ? "P-256" : null, l = this.kp.get(i.ks?.group);
                    if (!c || !i.ks?.key?.length || !l) throw new Error;
                    const a = this.cc.hash, w = j(a), {keyLen: p, ivLen: y} = this.cc, P2 = await $(l.kp.privateKey, i.ks.key, c), U = await q(a, await V(a, null, new Uint8Array(w)), "derived", await M(a, L), w);
                    this.hs = await V(a, U, P2);
                    const d = await M(a, this.ts()), C = await q(a, this.hs, "c hs traffic", d, w), H = await q(a, this.hs, "s hs traffic", d, w);
                    [this.ch, this.ci] = await T(a, C, p, y, "encrypt"), [this.sh, this.si] = await T(a, H, p, y, "decrypt");
                    let E = !1, x = !1;
                    await this.pr(async k => {
                        if (k.type === 20 || k.type === 22) return;
                        if (k.type === 21) {
                            if (D(k.fragment)) return;
                            throw new Error
                        }
                        if (k.type !== 23) return;
                        const bt = await N(this.sh, I(this.si, this.fs()), k.fragment, new Uint8Array([23, 3, 3, ...f(k.fragment.length)])), {data: dt, type: kt} = Q(bt);
                        if (kt === 22) {
                            this.hp.feed(dt);
                            for (let st; st = this.hp.next();) if (this.rh(st.raw), st.type === 13) x = !0; else if (st.type === 20) return E = !0, 1
                        }
                    });
                    const o = await M(a, this.ts()), A = await q(a, this.hs, "derived", await M(a, L), w), X = await V(a, A, new Uint8Array(w));
                    [this.ak, this.ai] = await T(a, await q(a, X, "c ap traffic", o, w), p, y, "encrypt"), [this.bk, this.bi] = await T(a, await q(a, X, "s ap traffic", o, w), p, y, "decrypt");
                    let F = L;
                    x && (F = K(11, [0, 0, 0, 0]), this.rh(F));
                    const wt = await q(a, C, "finished", L, w), tt = K(20, await B(a, wt, await M(a, this.ts())));
                    this.rh(tt);
                    const J = b(F, tt, [22]);
                    await this.wr.write(v(23, await R(this.ch, I(this.ci, this.fc()), J, new Uint8Array([23, 3, 3, ...f(J.length + 16)])))), this.cn = this.qn = 0n
                } else {
                    let r = null, c = !1, l = !1;
                    const a = async o => {
                        if (this.rh(o.raw), o.type === 12) {
                            r = {nc: _(o.body, 1), spk: o.body.subarray(4, 4 + o.body[3])};
                        } else {
                            if (o.type === 14) return c = !0, 1;
                            o.type === 13 && (l = !0)
                        }
                    };
                    let w = !1;
                    for (let o; o = this.hp.next();) if (await a(o)) {
                        w = !0;
                        break
                    }
                    if (w || await this.pr(async o => {
                        if (o.type === 21) {
                            if (D(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 22) {
                            this.hp.feed(o.fragment);
                            for (let A; A = this.hp.next();) if (await a(A)) return 1
                        }
                    }), !c || !r) {
                        throw new Error;
                    }
                    const p = r.nc === 29 ? "X25519" : r.nc === 23 ? "P-256" : null, y = this.kp.get(r.nc);
                    if (!p || !y) throw new Error;
                    if (l) {
                        const o = K(11, [0, 0, 0]);
                        this.rh(o), await this.wr.write(v(22, o))
                    }
                    const P2 = await $(y.kp.privateKey, r.spk, p), g = K(16, b([y.pk.length], y.pk));
                    this.rh(g);
                    const U = this.cc.hash;
                    this.ms = await G(P2, "master secret", b(this.cr, this.sr), 48, U);
                    const {keyLen: d, ivLen: C} = this.cc, H = await G(this.ms, "key expansion", b(this.sr, this.cr), 2 * d + 2 * C, U);
                    [this.ck, this.wk] = await Promise.all([W(H.subarray(0, d), "encrypt"), W(H.subarray(d, 2 * d), "decrypt")]), this.cv = H.subarray(2 * d, 2 * d + C), this.wv = H.subarray(2 * d + C, 2 * d + 2 * C), await this.wr.write(v(22, g)), await this.wr.write(v(20, [1]));
                    const E = await G(this.ms, "client finished", await M(U, this.ts()), 12, U), x = K(20, E);
                    this.rh(x), await this.wr.write(v(22, await this.e12(x, 22)));
                    let S = !1;
                    await this.pr(async o => {
                        if (o.type === 21) {
                            if (D(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) return void (S = !0);
                        if (o.type === 22 && S && (await this.d12(o.fragment, 22))[0] === 20) return 1
                    })
                }
                this.hc = !0, this.cr = this.id = this.sr = this.ms = this.hs = this.ch = this.sh = this.ci = this.si = null, this.kp.clear(), this.kp = null
            } finally {
                if (!this.hc || this.fl) {
                    try {this.rd?.releaseLock()} catch {}
                    try {this.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            for (; ;) {
                const {value: t, done: s} = await this.rc();
                if (s) throw new Error;
                this.rp.feed(t);
                for (let h; h = this.rp.next();) {
                    if (h.type === 21) {
                        if (D(h.fragment)) continue;
                        throw new Error
                    }
                    if (h.type === 22) {
                        this.hp.feed(h.fragment);
                        for (let e; e = this.hp.next();) {
                            if (e.type !== 2) continue;
                            this.rh(e.raw);
                            let i = 2;
                            const r = _(e.body, 0), c = e.body.slice(i, i += 32), l = e.body[i++], a = e.body.subarray(i, i += l), w = _(e.body, i);
                            i += 2;
                            const p = e.body[i++];
                            let y = r, P2 = null;
                            if (i < e.body.length) {
                                const C = i + 2 + _(e.body, i);
                                for (i += 2; i + 4 <= C;) {
                                    const H = _(e.body, i), E = _(e.body, i + 2), x = e.body.subarray(i += 4, i += E);
                                    H === 43 && E >= 2 ? y = _(x, 0) : H === 51 && E >= 2 && (P2 = {group: _(x, 0), key: E >= 4 ? x.subarray(4, 4 + _(x, 2)) : L})
                                }
                            }
                            const g = {version: r, sr: c, sid: a, cs: w, comp: p, sv: y, ks: P2, isTls13: y === 772},
                                U = {4865: {id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0}, 4866: {id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0}, 49199: {id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}, 49200: {id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}, 49195: {id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}, 49196: {id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}}[g.cs];
                            if (!U || g.comp || g.isTls13 !== !!U.tls13 || !g.isTls13 && g.sv !== 771) throw new Error;
                            return this.sr = g.sr, this.cs = g.cs, this.cc = U, this.i3 = g.isTls13, g
                        }
                    }
                }
            }
        }
        async e12(t, s, h = this.fc()) {
            const e = new Uint8Array(8);
            return new DataView(e.buffer).setBigUint64(0, h), b(e, await R(this.ck, b(this.cv, e), t, u(e, s, 3, 3, f(t.length))))
        }
        async d12(t, s, h = this.fs()) {
            const e = new Uint8Array(8), i = t.subarray(0, 8), r = t.subarray(8);
            return new DataView(e.buffer).setBigUint64(0, h), N(this.wk, b(this.wv, i), r, u(e, s, 3, 3, f(r.length - 16)))
        }
        async e13(t, s = this.fc(), h = 23) {
            const e = new Uint8Array(t.length + 1);
            return e.set(t), e[t.length] = h, R(this.ak, I(this.ai, s), e, new Uint8Array([23, 3, 3, ...f(e.length + 16)]))
        }
        async d13(t, s = this.fs(), h = this.bk, e = this.bi) {return Q(await N(h, I(e, s), t, new Uint8Array([23, 3, 3, ...f(t.length)])))}
        write(t) {
            if (!this.hc || this.fl || this.cg) return Promise.reject(new Error);
            const s = this.wq.then(async () => {
                if (this.fl || this.cg) throw new Error;
                if (t.length <= 16384) return this.wr.write(v(23, this.i3 ? await this.e13(t) : await this.e12(t, 23)));
                for (let e = 0; e < t.length;) {
                    const i = [];
                    for (let r = 0; r < 8 && e < t.length; r++, e += 16384) {
                        const c = t.subarray(e, Math.min(e + 16384, t.length)), l = this.fc();
                        i.push((this.i3 ? this.e13(c, l) : this.e12(c, 23, l)).then(a => v(23, a)))
                    }
                    await this.wr.write(b(...await Promise.all(i)))
                }
            }), h = s.catch(e => {throw this.fail(), e});
            return this.wq = h.catch(() => {}), h
        }
        read() {
            return this.fl || !this.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (this.pq.length) return this.pq.length === 1 ? this.pq.pop() : b(...this.pq.splice(0));
                    if (this.cl) return null;
                    const t = [];
                    for (let s; t.length < 8 && (s = this.rp.next());) if (!(this.i3 ? s.type === 20 : ![21, 22, 23].includes(s.type))) {
                        if (this.i3 && s.type !== 23) throw new Error;
                        t.push(s)
                    }
                    if (t.length) {
                        if (this.i3) {
                            const i = this.qn, r = this.bk, c = this.bi;
                            let l;
                            try {l = await Promise.all(t.map((a, w) => this.d13(a.fragment, i + BigInt(w), r, c)))} catch {}
                            if (l) {
                                this.qn = i + BigInt(l.length);
                                for (const x of l) this.p13(x)
                            } else {
                                for (let a = 0; a < t.length; a++) this.p13(await this.d13(t[a].fragment, this.qn++))
                            }
                        } else {
                            const i = this.qn, r = await Promise.all(t.map((c, l) => this.d12(c.fragment, c.type, i + BigInt(l))));
                            this.qn = i + BigInt(t.length);
                            for (let c = 0; c < r.length; c++) {
                                const l = r[c], a = t[c].type;
                                if (a === 23) this.pq.push(l); else if (a === 21) this.pa(l); else if (a === 22) for (this.hp.feed(l); this.hp.next();) ;
                            }
                        }
                        if (this.pq.length) return this.pq.length === 1 ? this.pq.pop() : b(...this.pq.splice(0));
                        if (this.cl) return null;
                        continue
                    }
                    if (this.cl) return null;
                    const {value: h, done: e} = await this.rc();
                    if (e) return null;
                    this.rp.feed(h)
                }
            })().catch(t => {throw this.fail(), t})
        }
        pa(t) {this.cl = !0, this.close()}
        p13({data: t, type: s}) {s === 23 ? this.pq.push(t) : s === 21 && this.pa(t)}
        close() {
            return this.cp ? this.cp : this.fl || !this.hc ? (this.sk?.close(), this.cp = Promise.resolve()) : (this.cg = !0, this.wq = this.cp = this.wq.then(async () => {
                const s = new Uint8Array([1, 0]), h = this.i3 ? await this.e13(s, this.fc(), 21) : await this.e12(s, 21);
                await this.wr.write(v(this.i3 ? 23 : 21, h))
            }).catch(() => {}).finally(() => {this.cl = !0, this.sk?.close()}))
        }
    }
    return {TlsClient: lt}
})();
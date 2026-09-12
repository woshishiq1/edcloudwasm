export const {TlsClient} = (() => {
    const V = new TextEncoder, q = new Uint8Array, p = (...e) => {
            const t = [], i = h => h.forEach(s => s instanceof Uint8Array ? t.push(...s) : Array.isArray(s) ? i(s) : t.push(s));
            return i(e), new Uint8Array(t)
        }, o = e => [e >> 8, e & 255], b = (e, t) => e[t] << 8 | e[t + 1], y = (...e) => {
            const t = new Uint8Array(e.reduce((h, s) => h + (s?.length || 0), 0));
            let i = 0;
            for (const h of e) h?.length && (t.set(h, i), i += h.length);
            return t
        }, G = e => e === "SHA-384" ? 48 : 32, K = e => e?.[0] === 1 && e[1] === 112, M = async (e, t, i) => new Uint8Array(await crypto.subtle.sign("HMAC", t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]), i)), C = async (e, t) => new Uint8Array(await crypto.subtle.digest(e, t)), R = (e, t) => crypto.subtle.importKey("raw", e, {name: "AES-GCM"}, !1, [t]),
        j = async (e, t, i, h) => new Uint8Array(await crypto.subtle.encrypt({name: "AES-GCM", iv: t, additionalData: h}, e, i)), N = async (e, t, i, h) => new Uint8Array(await crypto.subtle.decrypt({name: "AES-GCM", iv: t, additionalData: h}, e, i)), v = (e, t, i = 771) => {
            const h = new Uint8Array(5 + t.length);
            return h.set([e, i >> 8, i, t.length >> 8, t.length]), h.set(t, 5), h
        }, L = (e, t) => {
            const i = new Uint8Array(4 + t.length), h = t.length;
            return i.set([e, h >> 16, h >> 8, h]), i.set(t, 4), i
        };
    async function W(e, t, i, h, s = "SHA-256") {
        const n = y(V.encode(t), i), a = e.type ? e : await crypto.subtle.importKey("raw", e, {name: "HMAC", hash: s}, !1, ["sign"]);
        let c = new Uint8Array(0), r = n;
        for (; c.length < h;) r = await M(s, a, r), c = y(c, await M(s, a, y(r, n)));
        return c.slice(0, h)
    }
    const F = (e, t, i) => M(e, t?.length ? t : new Uint8Array(G(e)), i);
    async function U(e, t, i, h, s) {
        const n = typeof i == "string" ? V.encode("tls13 " + i) : i, a = G(e), c = p(o(s), n.length, n, h.length, h), r = t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]);
        let w = new Uint8Array(0), u = new Uint8Array(0);
        for (let g = 1; g <= Math.ceil(s / a); g++) u = await M(e, r, y(u, c, [g])), w = y(w, u);
        return w.slice(0, s)
    }
    const J = async (e = "P-256") => {
        const t = e === "X25519", i = await crypto.subtle.generateKey(t ? {name: e} : {name: "ECDH", namedCurve: e}, !0, ["deriveBits"]);
        return {kp: i, pk: new Uint8Array(await crypto.subtle.exportKey("raw", i.publicKey))}
    }, Q = async (e, t, i = "P-256") => {
        const h = i === "X25519", s = await crypto.subtle.importKey("raw", t, h ? {name: i} : {name: "ECDH", namedCurve: i}, !1, []);
        return new Uint8Array(await crypto.subtle.deriveBits({name: h ? i : "ECDH", public: s}, e, 256))
    };
    class Z {
        constructor(t) {this.b = new Uint8Array(t), this.h = this.t = 0}
        feed(t) {
            if (this.t + t.length > this.b.length) {
                const i = this.t - this.h, h = i + t.length > this.b.length, s = h ? new Uint8Array(Math.max(this.b.length * 2, i + t.length)) : this.b;
                h ? s.set(this.b.subarray(this.h, this.t)) : s.copyWithin(0, this.h, this.t), this.b = s, this.t = i, this.h = 0
            }
            this.b.set(t, this.t), this.t += t.length
        }
    }
    class O extends Z {
        constructor() {super(32768)}
        next() {
            if (this.t - this.h < 5) return null;
            const t = this.b[this.h], i = b(this.b, this.h + 1), h = b(this.b, this.h + 3);
            if (h > 18432) throw new Error;
            if (this.t - this.h < 5 + h) return null;
            const s = this.b.subarray(this.h + 5, this.h += 5 + h);
            return this.h === this.t && (this.h = this.t = 0), {type: t, version: i, length: h, fragment: s}
        }
    }
    class Y extends Z {
        constructor() {super(4096)}
        next() {
            if (this.t - this.h < 4) return null;
            const t = this.b[this.h], i = this.b[this.h + 1] << 16 | b(this.b, this.h + 2);
            if (this.t - this.h < 4 + i) return null;
            const h = this.b.subarray(this.h + 4, this.h + 4 + i), s = this.b.subarray(this.h, this.h += 4 + i);
            return this.h === this.t && (this.h = this.t = 0), {type: t, length: i, body: h, raw: s}
        }
    }
    function tt(e, t, i, {sessionId: h = q} = {}) {
        const s = p(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(o)), n = [p(255, 1, 0, 1, 0)];
        if (t) {
            const r = V.encode(t);
            n.push(p(0, 0, o(r.length + 5), o(r.length + 3), 0, o(r.length), r))
        }
        const a = y(p(0, 29, o(i.x25519.length), i.x25519), p(0, 23, o(i.p256.length), i.p256));
        n.push(p(o(11), 0, 2, 1, 0), p(o(10), 0, 6, 0, 4, 0, 29, 0, 23), p(o(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(o)), p(o(43), 0, 5, 4, 3, 4, 3, 3), p(o(45), 0, 2, 1, 1), p(o(51), o(a.length + 2), o(a.length), a));
        const c = y(...n);
        return L(1, p(o(771), e, h.length, h, o(s.length), s, 1, 0, o(c.length), c))
    }
    const S = async (e, t, i, h, s) => {
        const n = t.type ? t : await crypto.subtle.importKey("raw", t, {name: "HMAC", hash: e}, !1, ["sign"]), [a, c] = await Promise.all([U(e, n, "key", q, i), U(e, n, "iv", q, h)]);
        return [await R(a, s), c]
    }, _ = e => {
        let t = e.length - 1;
        for (; t >= 0 && !e[t];) t--;
        if (t < 0) throw new Error;
        return {data: e.subarray(0, t), type: e[t]}
    }, B = (e, t) => {
        const i = e.slice();
        for (let h = 0; h < 8; h++) i[i.length - 1 - h] ^= Number(t >> BigInt(h << 3) & 0xffn);
        return i
    };
    class it {
        constructor(t, i = {}) {this.sk = t, this.sn = i.serverName || "", this.cr = crypto.getRandomValues(new Uint8Array(32)), this.id = crypto.getRandomValues(new Uint8Array(32)), this.sr = this.ms = this.hs = this.ck = this.wk = this.cv = this.wv = this.ch = this.sh = this.ci = this.si = this.ak = this.bk = this.ai = this.bi = this.cp = this.rd = this.wr = this.cs = this.cc = null, this.hb = new Uint8Array(8192), this.hl = 0, this.hc = this.i3 = this.cl = this.cg = this.fl = !1, this.cn = this.qn = 0n, this.rp = new O, this.hp = new Y, this.kp = new Map, this.pq = [], this.wq = Promise.resolve(), this.rb = new Uint8Array(65536)}
        rh(t) {
            if (this.hl + t.length > this.hb.length) {
                const i = new Uint8Array(Math.max(this.hb.length * 2, this.hl + t.length));
                i.set(this.hb.subarray(0, this.hl)), this.hb = i
            }
            this.hb.set(t, this.hl), this.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {
            this.fl = this.cl = !0;
            try {this.rd?.cancel()} catch {}
            try {this.rd?.releaseLock()} catch {}
            try {this.wr?.releaseLock()} catch {}
            try {this.sk?.close()} catch {}
        }
        async rc() {
            const t = await this.rd.read(this.rb);
            if (!t) throw new Error;
            return !t.done && t.value && (this.rb = new Uint8Array(t.value.buffer)), t
        }
        async pr(t) {
            for (; ;) {
                for (let s; s = this.rp.next();) if (await t(s)) return;
                const {value: i, done: h} = await this.rc();
                if (h) throw new Error;
                this.rp.feed(i)
            }
        }
        async handshake() {
            const [t, i] = await Promise.all([J("P-256"), J("X25519")]);
            this.kp = new Map([[23, t], [29, i]]), this.rd = this.sk.readable.getReader({mode: "byob"}), this.wr = this.sk.writable.getWriter();
            try {
                const h = {p256: t.pk, x25519: i.pk}, s = tt(this.cr, this.sn, h, {sessionId: this.id});
                this.rh(s), await this.wr.write(v(22, s, 769));
                const n = await this.rsh();
                if (n.isTls13) {
                    const a = n.ks?.group === 29 ? "X25519" : n.ks?.group === 23 ? "P-256" : null, c = this.kp.get(n.ks?.group);
                    if (!a || !n.ks?.key?.length || !c) throw new Error;
                    const r = this.cc.hash, w = G(r), {keyLen: u, ivLen: g} = this.cc, A = await Q(c.kp.privateKey, n.ks.key, a), P = await U(r, await F(r, null, new Uint8Array(w)), "derived", await C(r, q), w);
                    this.hs = await F(r, P, A);
                    const f = await C(r, this.ts()), k = await U(r, this.hs, "c hs traffic", f, w), d = await U(r, this.hs, "s hs traffic", f, w);
                    [this.ch, this.ci] = await S(r, k, u, g, "encrypt"), [this.sh, this.si] = await S(r, d, u, g, "decrypt");
                    let E = !1, m = !1;
                    await this.pr(async H => {
                        if (H.type === 20 || H.type === 22) return;
                        if (H.type === 21) {
                            if (K(H.fragment)) return;
                            throw new Error
                        }
                        if (H.type !== 23) return;
                        const st = await N(this.sh, B(this.si, this.fs()), H.fragment, new Uint8Array([23, 3, 3, ...o(H.fragment.length)])), {data: ht, type: et} = _(st);
                        if (et === 22) {
                            this.hp.feed(ht);
                            for (let X; X = this.hp.next();) if (this.rh(X.raw), X.type === 13) m = !0; else if (X.type === 20) return E = !0, 1
                        }
                    });
                    const x = await C(r, this.ts()), T = await U(r, this.hs, "derived", await C(r, q), w), D = await F(r, T, new Uint8Array(w));
                    [this.ak, this.ai] = await S(r, await U(r, D, "c ap traffic", x, w), u, g, "encrypt"), [this.bk, this.bi] = await S(r, await U(r, D, "s ap traffic", x, w), u, g, "decrypt");
                    let l = q;
                    m && (l = L(11, [0, 0, 0, 0]), this.rh(l));
                    const I = await U(r, k, "finished", q, w), $ = L(20, await M(r, I, await C(r, this.ts())));
                    this.rh($);
                    const z = y(l, $, [22]);
                    await this.wr.write(v(23, await j(this.ch, B(this.ci, this.fc()), z, new Uint8Array([23, 3, 3, ...o(z.length + 16)])))), this.cn = this.qn = 0n
                } else {
                    let a = null, c = !1, r = !1;
                    const w = async l => {
                        if (this.rh(l.raw), l.type === 12) {
                            a = {nc: b(l.body, 1), spk: l.body.subarray(4, 4 + l.body[3])};
                        } else {
                            if (l.type === 14) return c = !0, 1;
                            l.type === 13 && (r = !0)
                        }
                    };
                    let u = !1;
                    for (let l; l = this.hp.next();) if (await w(l)) {
                        u = !0;
                        break
                    }
                    if (u || await this.pr(async l => {
                        if (l.type === 21) {
                            if (K(l.fragment)) return;
                            throw new Error
                        }
                        if (l.type === 22) {
                            this.hp.feed(l.fragment);
                            for (let I; I = this.hp.next();) if (await w(I)) return 1
                        }
                    }), !c || !a) {
                        throw new Error;
                    }
                    const g = a.nc === 29 ? "X25519" : a.nc === 23 ? "P-256" : null, A = this.kp.get(a.nc);
                    if (!g || !A) throw new Error;
                    if (r) {
                        const l = L(11, [0, 0, 0]);
                        this.rh(l), await this.wr.write(v(22, l))
                    }
                    const P = await Q(A.kp.privateKey, a.spk, g), f = L(16, y([A.pk.length], A.pk));
                    this.rh(f);
                    const k = this.cc.hash;
                    this.ms = await W(P, "master secret", y(this.cr, this.sr), 48, k);
                    const {keyLen: d, ivLen: E} = this.cc, m = await W(this.ms, "key expansion", y(this.sr, this.cr), 2 * d + 2 * E, k);
                    [this.ck, this.wk] = await Promise.all([R(m.subarray(0, d), "encrypt"), R(m.subarray(d, 2 * d), "decrypt")]), this.cv = m.subarray(2 * d, 2 * d + E), this.wv = m.subarray(2 * d + E, 2 * d + 2 * E), await this.wr.write(v(22, f)), await this.wr.write(v(20, [1]));
                    const x = await W(this.ms, "client finished", await C(k, this.ts()), 12, k), T = L(20, x);
                    this.rh(T), await this.wr.write(v(22, await this.e12(T, 22)));
                    let D = !1;
                    await this.pr(async l => {
                        if (l.type === 21) {
                            if (K(l.fragment)) return;
                            throw new Error
                        }
                        if (l.type === 20) return void (D = !0);
                        if (l.type === 22 && D && (await this.d12(l.fragment, 22))[0] === 20) return 1
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
                const {value: t, done: i} = await this.rc();
                if (i) throw new Error;
                this.rp.feed(t);
                for (let h; h = this.rp.next();) {
                    if (h.type === 21) {
                        if (K(h.fragment)) continue;
                        throw new Error
                    }
                    if (h.type === 22) {
                        this.hp.feed(h.fragment);
                        for (let s; s = this.hp.next();) {
                            if (s.type !== 2) continue;
                            this.rh(s.raw);
                            let n = 2;
                            const a = b(s.body, 0), c = s.body.slice(n, n += 32), r = s.body[n++], w = s.body.subarray(n, n += r), u = b(s.body, n);
                            n += 2;
                            const g = s.body[n++];
                            let A = a, P = null;
                            if (n < s.body.length) {
                                const d = n + 2 + b(s.body, n);
                                for (n += 2; n + 4 <= d;) {
                                    const E = b(s.body, n), m = b(s.body, n + 2), x = s.body.subarray(n += 4, n += m);
                                    E === 43 && m >= 2 ? A = b(x, 0) : E === 51 && m >= 2 && (P = {group: b(x, 0), key: m >= 4 ? x.subarray(4, 4 + b(x, 2)) : q})
                                }
                            }
                            const f = {version: a, sr: c, sid: w, cs: u, comp: g, sv: A, ks: P, isTls13: A === 772},
                                k = {4865: {id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0}, 4866: {id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0}, 49199: {id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}, 49200: {id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}, 49195: {id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE"}, 49196: {id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE"}}[f.cs];
                            if (!k || f.comp || f.isTls13 !== !!k.tls13 || !f.isTls13 && f.sv !== 771) throw new Error;
                            return this.sr = f.sr, this.cs = f.cs, this.cc = k, this.i3 = f.isTls13, f
                        }
                    }
                }
            }
        }
        async e12(t, i, h = this.fc()) {
            const s = new Uint8Array(8);
            return new DataView(s.buffer).setBigUint64(0, h), y(s, await j(this.ck, y(this.cv, s), t, p(s, i, 3, 3, o(t.length))))
        }
        async d12(t, i, h = this.fs()) {
            const s = new Uint8Array(8), n = t.subarray(0, 8), a = t.subarray(8);
            return new DataView(s.buffer).setBigUint64(0, h), N(this.wk, y(this.wv, n), a, p(s, i, 3, 3, o(a.length - 16)))
        }
        async e13(t, i = this.fc(), h = 23) {
            const s = new Uint8Array(t.length + 1);
            return s.set(t), s[t.length] = h, j(this.ak, B(this.ai, i), s, new Uint8Array([23, 3, 3, ...o(s.length + 16)]))
        }
        async d13(t, i = this.fs(), h = this.bk, s = this.bi) {return _(await N(h, B(s, i), t, new Uint8Array([23, 3, 3, ...o(t.length)])))}
        write(t) {
            if (!this.hc || this.fl || this.cg) return Promise.reject(new Error);
            const i = this.wq.then(async () => {
                if (this.fl || this.cg) throw new Error;
                if (t.length <= 16384) return this.wr.write(v(23, this.i3 ? await this.e13(t) : await this.e12(t, 23)));
                for (let s = 0; s < t.length;) {
                    const n = [];
                    for (let a = 0; a < 8 && s < t.length; a++, s += 16384) {
                        const c = t.subarray(s, Math.min(s + 16384, t.length)), r = this.fc();
                        n.push((this.i3 ? this.e13(c, r) : this.e12(c, 23, r)).then(w => v(23, w)))
                    }
                    await this.wr.write(y(...await Promise.all(n)))
                }
            }), h = i.catch(s => {throw this.fail(), s});
            return this.wq = h.catch(() => {}), h
        }
        read() {
            return this.fl || !this.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (this.pq.length) return this.pq.length === 1 ? this.pq.pop() : y(...this.pq.splice(0));
                    if (this.cl) return null;
                    const t = [];
                    for (let s; t.length < 8 && (s = this.rp.next());) if (!(this.i3 ? s.type === 20 : ![21, 22, 23].includes(s.type))) {
                        if (this.i3 && s.type !== 23) throw new Error;
                        t.push(s)
                    }
                    if (t.length) {
                        if (this.i3) {
                            const s = this.qn, n = this.bk, a = this.bi;
                            let c;
                            try {c = await Promise.all(t.map((r, w) => this.d13(r.fragment, s + BigInt(w), n, a)))} catch {}
                            if (c) {
                                this.qn = s + BigInt(c.length);
                                for (const r of c) this.p13(r)
                            } else {
                                for (let r = 0; r < t.length; r++) this.p13(await this.d13(t[r].fragment, this.qn++))
                            }
                        } else {
                            const s = this.qn, n = await Promise.all(t.map((a, c) => this.d12(a.fragment, a.type, s + BigInt(c))));
                            this.qn = s + BigInt(t.length);
                            for (let a = 0; a < n.length; a++) {
                                const c = n[a], r = t[a].type;
                                if (r === 23) this.pq.push(c); else if (r === 21) this.pa(c); else if (r === 22) for (this.hp.feed(c); this.hp.next();) ;
                            }
                        }
                        if (this.pq.length) return this.pq.length === 1 ? this.pq.pop() : y(...this.pq.splice(0));
                        if (this.cl) return null;
                        continue
                    }
                    if (this.cl) return null;
                    const {value: i, done: h} = await this.rc();
                    if (h) return null;
                    this.rp.feed(i)
                }
            })().catch(t => {throw this.fail(), t})
        }
        pa(t) {
            if (this.cl = !0, t && t.length >= 2) {
                const i = t[0], h = t[1];
                if (i === 2 || i === 1 && h !== 0) throw this.fail(), new Error
            }
            this.close()
        }
        p13({data: t, type: i}) {i === 23 ? this.pq.push(t) : i === 21 && this.pa(t)}
        close() {
            return this.cp ? this.cp : this.fl || !this.hc ? (this.sk?.close(), this.cp = Promise.resolve()) : (this.cg = !0, this.wq = this.cp = this.wq.then(async () => {
                const t = new Uint8Array([1, 0]), i = this.i3 ? await this.e13(t, this.fc(), 21) : await this.e12(t, 21);
                await this.wr.write(v(this.i3 ? 23 : 21, i))
            }).catch(() => {}).finally(() => {this.cl = !0, this.sk?.close()}))
        }
    }
    return {TlsClient: it}
})();

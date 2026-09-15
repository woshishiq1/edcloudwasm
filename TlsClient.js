export const {TlsClient} = (() => {
    const b = crypto.subtle, V = new TextEncoder, g = new Uint8Array(0), y = s => [s >> 8, s & 255], A = (s, t) => s[t] << 8 | s[t + 1], E = (...s) => {
            const t = n => {
                let i = 0;
                for (let c = 0; c < n.length; c++) {
                    const l = n[c];
                    i += l instanceof Uint8Array ? l.length : Array.isArray(l) ? t(l) : 1
                }
                return i
            }, e = new Uint8Array(t(s));
            let r = 0;
            const a = n => {
                for (let i = 0; i < n.length; i++) {
                    const c = n[i];
                    c instanceof Uint8Array ? (e.set(c, r), r += c.length) : Array.isArray(c) ? a(c) : e[r++] = c
                }
            };
            return a(s), e
        }, d = (...s) => {
            const t = new Uint8Array(s.reduce((r, a) => r + (a?.length || 0), 0));
            let e = 0;
            for (const r of s) r?.length && (t.set(r, e), e += r.length);
            return t
        }, D = s => s === "SHA-384" ? 48 : 32, B = s => s?.[0] === 1 && s[1] === 112, j = async (s, t, e) => new Uint8Array(await b.sign("HMAC", t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), e)), K = async (s, t) => new Uint8Array(await b.digest(s, t)), W = (s, t) => b.importKey("raw", s, {name: "AES-GCM"}, !1, [t]), z = async (s, t, e, r) => new Uint8Array(await b.encrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)),
        N = async (s, t, e, r) => new Uint8Array(await b.decrypt({name: "AES-GCM", iv: t, additionalData: r}, s, e)), M = (s, t, e = 771, r = t.length) => {
            const a = new Uint8Array(5 + r);
            return a[0] = s, a[1] = e >> 8, a[2] = e & 255, a[3] = r >> 8, a[4] = r & 255, a.set(t, 5), a
        }, $ = (s, t = 23) => {
            let e = 0;
            for (let n = 0; n < s.length; n++) e += 5 + s[n].length;
            const r = new Uint8Array(e);
            let a = 0;
            for (let n = 0; n < s.length; n++) {
                const i = s[n], c = i.length;
                r[a] = t, r[a + 1] = 3, r[a + 2] = 3, r[a + 3] = c >> 8, r[a + 4] = c & 255, r.set(i, a + 5), a += 5 + c
            }
            return r
        }, L = (s, t, e = t.length) => {
            const r = new Uint8Array(4 + e);
            return r[0] = s, r[1] = e >> 16 & 255, r[2] = e >> 8 & 255, r[3] = e & 255, r.set(t, 4), r
        }, G = s => new Uint8Array([23, 3, 3, s >> 8, s & 255]), tt = s => {
            const t = new Uint8Array(8), e = s >>> 0;
            if (t[7] = e & 255, t[6] = e >>> 8 & 255, t[5] = e >>> 16 & 255, t[4] = e >>> 24, s > 4294967295) {
                const r = Math.floor(s / 4294967296) >>> 0;
                t[3] = r & 255, t[2] = r >>> 8 & 255, t[1] = r >>> 16 & 255, t[0] = r >>> 24
            }
            return t
        }, F = (s, t, e) => j(s, t?.length ? t : new Uint8Array(D(s)), e), J = async (s, t, e, r, a = "SHA-256") => {
            const n = d(V.encode(t), e), i = s.type ? s : await b.importKey("raw", s, {name: "HMAC", hash: a}, !1, ["sign"]);
            let c = g, l = n;
            for (; c.length < r;) l = await j(a, i, l), c = d(c, await j(a, i, d(l, n)));
            return c.slice(0, r)
        }, x = async (s, t, e, r, a) => {
            const n = typeof e == "string" ? V.encode("tls13 " + e) : e, i = D(s), c = n.length, l = r.length, h = new Uint8Array(4 + c + l);
            h[0] = a >> 8, h[1] = a & 255, h[2] = c, h.set(n, 3), h[3 + c] = l, l && h.set(r, 4 + c);
            const f = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]);
            let k = g, p = g;
            for (let U = 1; U <= Math.ceil(a / i); U++) {
                const v = new Uint8Array(p.length + h.length + 1);
                p.length && v.set(p), v.set(h, p.length), v[p.length + h.length] = U, p = await j(s, f, v), k = d(k, p)
            }
            return k.slice(0, a)
        }, Q = async (s = "P-256") => {
            const t = s === "X25519", e = await b.generateKey(t ? {name: s} : {name: "ECDH", namedCurve: s}, !0, ["deriveBits"]);
            return {kp: e, pk: new Uint8Array(await b.exportKey("raw", e.publicKey))}
        }, Y = async (s, t, e = "P-256") => {
            const r = e === "X25519", a = await b.importKey("raw", t, r ? {name: e} : {name: "ECDH", namedCurve: e}, !1, []);
            return new Uint8Array(await b.deriveBits({name: r ? e : "ECDH", public: a}, s, 256))
        };
    class Z {
        constructor(t, e, r) {this.b = new Uint8Array(t), this.h = this.t = 0, this.l = e, this.g = r}
        feed(t) {
            const e = this;
            if (e.t + t.length > e.b.length) {
                const r = e.t - e.h, a = r + t.length > e.b.length, n = a ? new Uint8Array(Math.max(e.b.length * 2, r + t.length)) : e.b;
                a ? n.set(e.b.subarray(e.h, e.t)) : n.copyWithin(0, e.h, e.t), e.b = n, e.t = r, e.h = 0
            }
            e.b.set(t, e.t), e.t += t.length
        }
        next() {
            const t = this;
            if (t.t - t.h < t.l) return null;
            const e = t.g(t.b, t.h);
            if (t.l === 5 && e > 18432) throw new Error;
            if (t.t - t.h < t.l + e) return null;
            const r = t.b.subarray(t.h, t.h += t.l + e), a = r.subarray(t.l);
            return t.h === t.t && (t.h = t.t = 0), {type: r[0], version: t.l === 5 ? A(r, 1) : 0, length: e, body: a, fragment: a, raw: r}
        }
    }
    const et = (s, t, e, {sessionId: r = g} = {}) => {
        const a = E(...[4865, 4866, 49199, 49200, 49195, 49196].flatMap(y)), n = [E(255, 1, 0, 1, 0)];
        if (t) {
            const l = V.encode(t);
            n.push(E(0, 0, y(l.length + 5), y(l.length + 3), 0, y(l.length), l))
        }
        const i = d(E(0, 29, y(e.x25519.length), e.x25519), E(0, 23, y(e.p256.length), e.p256));
        n.push(E(y(11), 0, 2, 1, 0), E(y(10), 0, 6, 0, 4, 0, 29, 0, 23), E(y(13), 0, 34, 0, 32, ...[2052, 2053, 2054, 2055, 2056, 2057, 2058, 2059, 1027, 1283, 1539, 1025, 1281, 1537, 513, 515].flatMap(y)), E(y(43), 0, 5, 4, 3, 4, 3, 3), E(y(51), y(i.length + 2), y(i.length), i));
        const c = d(...n);
        return L(1, E(y(771), s, r.length, r, y(a.length), a, 1, 0, y(c.length), c))
    }, T = async (s, t, e, r, a) => {
        const n = t.type ? t : await b.importKey("raw", t, {name: "HMAC", hash: s}, !1, ["sign"]), [i, c] = await Promise.all([x(s, n, "key", g, e), x(s, n, "iv", g, r)]);
        return [await W(i, a), c]
    }, _ = s => {
        let t = s.length - 1;
        for (; t >= 0 && !s[t];) t--;
        if (t < 0) throw new Error;
        return {data: s.subarray(0, t), type: s[t]}
    }, R = (s, t) => {
        const e = s.slice(), r = e.length, a = t >>> 0;
        if (e[r - 1] ^= a & 255, e[r - 2] ^= a >>> 8 & 255, e[r - 3] ^= a >>> 16 & 255, e[r - 4] ^= a >>> 24, t > 4294967295) {
            const n = Math.floor(t / 4294967296) >>> 0;
            e[r - 5] ^= n & 255, e[r - 6] ^= n >>> 8 & 255, e[r - 7] ^= n >>> 16 & 255, e[r - 8] ^= n >>> 24
        }
        return e
    };
    class rt {
        constructor(t, e = {}) {
            const r = this;
            r.sk = t, r.sn = e.serverName || "", r.cr = crypto.getRandomValues(new Uint8Array(32)), r.id = crypto.getRandomValues(new Uint8Array(32)), r.hb = new Uint8Array(8192), r.hl = 0, r.cn = 0, r.qn = 0, r.rp = new Z(32768, 5, (a, n) => A(a, n + 3)), r.hp = new Z(4096, 4, (a, n) => a[n + 1] << 16 | A(a, n + 2)), r.kp = new Map, r.pq = [], r.wq = Promise.resolve(), r.rb = new Uint8Array(65536), r.rd = null, r.wr = null, r.fl = !1, r.cl = !1, r.cg = !1, r.hc = !1, r.cp = null, r.i3 = !1, r.cs = null, r.cc = null, r.sr = null, r.hs = null, r.ch = null, r.ci = null, r.sh = null, r.si = null, r.ak = null, r.ai = null, r.bk = null, r.bi = null, r.ms = null, r.ck = null, r.wk = null, r.cv = null, r.wv = null, r.as = null, r.bs = null
        }
        rh(t) {
            const e = this;
            if (e.hl + t.length > e.hb.length) {
                const r = new Uint8Array(Math.max(e.hb.length * 2, e.hl + t.length));
                r.set(e.hb.subarray(0, e.hl)), e.hb = r
            }
            e.hb.set(t, e.hl), e.hl += t.length
        }
        ts() {return this.hb.subarray(0, this.hl)}
        fc() {return this.cn++}
        fs() {return this.qn++}
        fail() {
            const t = this;
            t.fl = t.cl = !0;
            try {t.sk?.close()} catch {}
            try {t.rd?.cancel()} catch {}
            try {t.wr?.abort()} catch {}
        }
        async rc() {
            const t = this, e = await t.rd.read(t.rb);
            if (!e) throw new Error;
            return !e.done && e.value && (t.rb = new Uint8Array(e.value.buffer)), e
        }
        async pr(t) {
            const e = this;
            for (; ;) {
                for (let n; n = e.rp.next();) if (await t(n)) return;
                const {value: r, done: a} = await e.rc();
                if (a) throw new Error;
                e.rp.feed(r)
            }
        }
        async handshake() {
            const t = this, [e, r] = await Promise.all([Q("P-256"), Q("X25519")]);
            t.kp = new Map([[23, e], [29, r]]), t.rd = t.sk.readable.getReader({mode: "byob"}), t.wr = t.sk.writable.getWriter();
            try {
                const a = et(t.cr, t.sn, {p256: e.pk, x25519: r.pk}, {sessionId: t.id});
                t.rh(a), await t.wr.write(M(22, a, 769));
                const n = await t.rsh();
                if (n.isTls13) {
                    const i = n.ks?.group === 29 ? "X25519" : n.ks?.group === 23 ? "P-256" : null, c = t.kp.get(n.ks?.group);
                    if (!i || !n.ks?.key?.length || !c) throw new Error;
                    const l = t.cc.hash, h = D(l), {keyLen: f, ivLen: k} = t.cc, p = await Y(c.kp.privateKey, n.ks.key, i), U = await x(l, await F(l, null, new Uint8Array(h)), "derived", await K(l, g), h);
                    t.hs = await F(l, U, p);
                    const v = await K(l, t.ts()), w = await x(l, t.hs, "c hs traffic", v, h), P = await x(l, t.hs, "s hs traffic", v, h);
                    [t.ch, t.ci] = await T(l, w, f, k, "encrypt"), [t.sh, t.si] = await T(l, P, f, k, "decrypt");
                    let m = !1;
                    await t.pr(async u => {
                        if (u.type === 20 || u.type === 22) return;
                        if (u.type === 21) {
                            if (B(u.fragment)) return;
                            throw new Error
                        }
                        if (u.type !== 23) return;
                        const {data: nt, type: at} = _(await N(t.sh, R(t.si, t.fs()), u.fragment, G(u.fragment.length)));
                        if (at === 22) {
                            t.hp.feed(nt);
                            for (let I; I = t.hp.next();) if (t.rh(I.raw), I.type === 13) m = !0; else if (I.type === 20) return 1
                        }
                    });
                    const C = await K(l, t.ts()), q = await x(l, t.hs, "derived", await K(l, g), h), H = await F(l, q, new Uint8Array(h));
                    t.as = await x(l, H, "c ap traffic", C, h), t.bs = await x(l, H, "s ap traffic", C, h), [t.ak, t.ai] = await T(l, t.as, f, k, "encrypt"), [t.bk, t.bi] = await T(l, t.bs, f, k, "decrypt");
                    let S = g;
                    m && (S = L(11, [0, 0, 0, 0]), t.rh(S));
                    const O = await x(l, w, "finished", g, h), X = L(20, await j(l, O, await K(l, t.ts())));
                    t.rh(X);
                    const o = d(S, X, [22]);
                    await t.wr.write(d(M(20, [1]), M(23, await z(t.ch, R(t.ci, t.fc()), o, G(o.length + 16))))), t.cn = t.qn = 0
                } else {
                    let i = null, c = !1, l = !1;
                    const h = async o => {
                        if (t.rh(o.raw), o.type === 12) {
                            i = {nc: A(o.body, 1), spk: o.body.subarray(4, 4 + o.body[3])};
                        } else {
                            if (o.type === 14) return c = !0, 1;
                            o.type === 13 && (l = !0)
                        }
                    };
                    let f = !1;
                    for (let o; o = t.hp.next();) if (await h(o)) {
                        f = !0;
                        break
                    }
                    if (!f) {
                        for (let o; o = t.rp.next();) if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) {
                                f = !0;
                                break
                            }
                            if (f) break
                        }
                    }
                    if (f || await t.pr(async o => {
                        if (o.type === 21) {
                            if (B(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) throw new Error;
                        if (o.type === 22) {
                            t.hp.feed(o.fragment);
                            for (let u; u = t.hp.next();) if (await h(u)) return 1
                        }
                    }), !c || !i) {
                        throw new Error;
                    }
                    const k = i.nc === 29 ? "X25519" : i.nc === 23 ? "P-256" : null, p = t.kp.get(i.nc);
                    if (!k || !p) throw new Error;
                    let U = g;
                    if (l) {
                        const o = L(11, [0, 0, 0]);
                        t.rh(o), U = M(22, o)
                    }
                    const v = await Y(p.kp.privateKey, i.spk, k), w = L(16, d([p.pk.length], p.pk));
                    t.rh(w);
                    const P = t.cc.hash;
                    t.ms = await J(v, "master secret", d(t.cr, t.sr), 48, P);
                    const {keyLen: m, ivLen: C} = t.cc, q = await J(t.ms, "key expansion", d(t.sr, t.cr), 2 * m + 2 * C, P);
                    [t.ck, t.wk] = await Promise.all([W(q.subarray(0, m), "encrypt"), W(q.subarray(m, 2 * m), "decrypt")]), t.cv = q.subarray(2 * m, 2 * m + C), t.wv = q.subarray(2 * m + C, 2 * m + 2 * C);
                    const H = await J(t.ms, "client finished", await K(P, t.ts()), 12, P), S = L(20, H);
                    t.rh(S);
                    const O = await t.e12(S, 22);
                    await t.wr.write(d(U, M(22, w), M(20, [1]), M(22, O)));
                    let X = !1;
                    await t.pr(async o => {
                        if (o.type === 21) {
                            if (B(o.fragment)) return;
                            throw new Error
                        }
                        if (o.type === 20) return void (X = !0);
                        if (o.type === 22 && X) {
                            t.hp.feed(await t.d12(o.fragment, 22));
                            for (let u; u = t.hp.next();) if (u.type === 20) return 1
                        }
                    })
                }
                t.hc = !0, t.cr = t.id = t.sr = t.ms = t.hs = t.ch = t.sh = t.ci = t.si = null, t.kp.clear(), t.kp = null
            } finally {
                if (!t.hc || t.fl) {
                    try {t.rd?.releaseLock()} catch {}
                    try {t.wr?.releaseLock()} catch {}
                }
            }
        }
        async rsh() {
            const t = this;
            for (; ;) {
                const {value: e, done: r} = await t.rc();
                if (r) throw new Error;
                t.rp.feed(e);
                for (let a; a = t.rp.next();) {
                    if (a.type === 21) {
                        if (B(a.fragment)) continue;
                        throw new Error
                    }
                    if (a.type !== 20 && a.type === 22) {
                        t.hp.feed(a.fragment);
                        for (let n; n = t.hp.next();) {
                            if (n.type !== 2) continue;
                            t.rh(n.raw);
                            let i = 2;
                            const c = A(n.body, 0), l = n.body.slice(i, i += 32), h = n.body[i++], f = n.body.subarray(i, i += h), k = A(n.body, i);
                            i += 2;
                            const p = n.body[i++];
                            let U = c, v = null;
                            if (i < n.body.length) {
                                const m = i + 2 + A(n.body, i);
                                for (i += 2; i + 4 <= m;) {
                                    const C = A(n.body, i), q = A(n.body, i + 2), H = n.body.subarray(i += 4, i += q);
                                    C === 43 && q >= 2 ? U = A(H, 0) : C === 51 && q >= 2 && (v = {group: A(H, 0), key: q >= 4 ? H.subarray(4, 4 + A(H, 2)) : g})
                                }
                            }
                            const w = {version: c, sr: l, sid: f, cs: k, comp: p, sv: U, ks: v, isTls13: U === 772}, P = w.cs === 4866 || w.cs === 49200 || w.cs === 49196;
                            if (!P && w.cs !== 4865 && w.cs !== 49199 && w.cs !== 49195 || p !== 0 || w.cs < 49e3 !== w.isTls13 || !w.isTls13 && w.sv !== 771) throw new Error;
                            return t.sr = w.sr, t.cs = w.cs, t.cc = {keyLen: P ? 32 : 16, ivLen: w.isTls13 ? 12 : 4, hash: P ? "SHA-384" : "SHA-256", tls13: w.isTls13}, t.i3 = w.isTls13, w
                        }
                    }
                }
            }
        }
        async e12(t, e, r = this.fc()) {
            const a = tt(r), n = new Uint8Array(12);
            n.set(this.cv), n.set(a, 4);
            const i = new Uint8Array(13);
            i.set(a), i[8] = e, i[9] = 3, i[10] = 3, i[11] = t.length >> 8, i[12] = t.length & 255;
            const c = await z(this.ck, n, t, i), l = new Uint8Array(8 + c.length);
            return l.set(a), l.set(c, 8), l
        }
        async d12(t, e, r = this.fs()) {
            const a = t.subarray(0, 8), n = t.subarray(8), i = new Uint8Array(12);
            i.set(this.wv), i.set(a, 4);
            const c = new Uint8Array(13), l = r >>> 0, h = n.length - 16;
            if (c[7] = l & 255, c[6] = l >>> 8 & 255, c[5] = l >>> 16 & 255, c[4] = l >>> 24, r > 4294967295) {
                const f = Math.floor(r / 4294967296) >>> 0;
                c[3] = f & 255, c[2] = f >>> 8 & 255, c[1] = f >>> 16 & 255, c[0] = f >>> 24
            }
            return c[8] = e, c[9] = 3, c[10] = 3, c[11] = h >> 8, c[12] = h & 255, N(this.wk, i, n, c)
        }
        async e13(t, e = this.fc(), r = 23) {
            const a = new Uint8Array(t.length + 1);
            return a.set(t), a[t.length] = r, z(this.ak, R(this.ai, e), a, G(a.length + 16))
        }
        async d13(t, e = this.fs(), r = this.bk, a = this.bi) {return _(await N(r, R(a, e), t, G(t.length)))}
        write(t) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = t instanceof Uint8Array ? t.slice() : new Uint8Array(t);
            if (!r.length) return Promise.resolve();
            const a = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                if (r.length <= 16384) return e.wr.write(M(23, e.i3 ? await e.e13(r) : await e.e12(r, 23)));
                for (let i = 0; i < r.length;) {
                    const c = [];
                    for (let l = 0; l < 8 && i < r.length; l++, i += 16384) {
                        const h = r.subarray(i, Math.min(i + 16384, r.length)), f = e.fc();
                        c.push(e.i3 ? e.e13(h, f) : e.e12(h, 23, f))
                    }
                    await e.wr.write($(await Promise.all(c)))
                }
            }), n = a.catch(i => {throw e.fail(), i});
            return e.wq = n.catch(() => {}), n
        }
        read() {
            const t = this;
            return t.fl || !t.hc ? Promise.reject(new Error) : (async () => {
                for (; ;) {
                    if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                    if (t.cl) return null;
                    const e = [];
                    for (let n; e.length < 8 && (n = t.rp.next());) if (!(t.i3 ? n.type === 20 : ![21, 22, 23].includes(n.type))) {
                        if (t.i3 && n.type !== 23) throw new Error;
                        e.push(n)
                    }
                    if (e.length) {
                        if (t.i3) {
                            const n = t.qn, i = t.bk, c = t.bi;
                            let l;
                            try {l = await Promise.all(e.map((h, f) => t.d13(h.fragment, n + f, i, c)))} catch {}
                            if (l) {
                                t.qn = n + l.length;
                                for (const h of l) await t.p13(h)
                            } else {
                                for (let h = 0; h < e.length; h++) await t.p13(await t.d13(e[h].fragment, t.qn++))
                            }
                        } else {
                            const n = t.qn, i = await Promise.all(e.map((c, l) => t.d12(c.fragment, c.type, n + l)));
                            t.qn = n + e.length;
                            for (let c = 0; c < i.length; c++) {
                                const l = i[c], h = e[c].type;
                                if (h === 23) t.pq.push(l); else if (h === 21) t.pa(l); else if (h === 22) for (t.hp.feed(l); t.hp.next();) ;
                            }
                        }
                        if (t.pq.length) return t.pq.length === 1 ? t.pq.pop() : d(...t.pq.splice(0));
                        if (t.cl) return null;
                        continue
                    }
                    if (t.cl) return null;
                    const {value: r, done: a} = await t.rc();
                    if (a) return null;
                    t.rp.feed(r)
                }
            })().catch(e => {throw t.fail(), e})
        }
        pa(t) {
            const e = this;
            if (e.cl = !0, t && t.length >= 2) {
                const r = t[0], a = t[1];
                if (r === 2 || r === 1 && a !== 0) throw e.fail(), new Error
            }
            e.close()
        }
        async p13({data: t, type: e}) {
            if (e === 23) {
                this.pq.push(t);
            } else if (e === 21) {
                this.pa(t);
            } else if (e === 22) {
                this.hp.feed(t);
                for (let r; r = this.hp.next();) r.type === 24 && (await this.uv(), r.body[0] === 1 && await this.su(0))
            }
        }
        async uk() {
            const t = this, e = t.cc.hash, r = D(e), {keyLen: a, ivLen: n} = t.cc;
            t.as = await x(e, t.as, "traffic upd", g, r), [t.ak, t.ai] = await T(e, t.as, a, n, "encrypt"), t.cn = 0
        }
        async uv() {
            const t = this, e = t.cc.hash, r = D(e), {keyLen: a, ivLen: n} = t.cc;
            t.bs = await x(e, t.bs, "traffic upd", g, r), [t.bk, t.bi] = await T(e, t.bs, a, n, "decrypt"), t.qn = 0
        }
        su(t = 0) {
            const e = this;
            if (!e.hc || e.fl || e.cg) return Promise.reject(new Error);
            const r = e.wq.then(async () => {
                if (e.fl || e.cg) throw new Error;
                const n = L(24, [t]);
                await e.wr.write(M(23, await e.e13(n, e.fc(), 22))), await e.uk()
            }), a = r.catch(n => {throw e.fail(), n});
            return e.wq = a.catch(() => {}), a
        }
        close() {
            const t = this;
            return t.cp ? t.cp : t.fl || !t.hc ? (t.sk?.close(), t.cp = Promise.resolve()) : (t.cg = !0, t.wq = t.cp = t.wq.then(async () => {
                const e = new Uint8Array([1, 0]), r = t.i3 ? await t.e13(e, t.fc(), 21) : await t.e12(e, 21);
                await t.wr.write(M(t.i3 ? 23 : 21, r))
            }).catch(() => {}).finally(() => {t.cl = !0, t.sk?.close()}))
        }
    }
    return {TlsClient: rt}
})();

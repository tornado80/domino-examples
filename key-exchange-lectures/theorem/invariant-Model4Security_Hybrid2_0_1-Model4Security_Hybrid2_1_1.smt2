; Hop 7 of Model4Security: Test switches from the handle key to a fresh key.
;
; Left (b = false) reads KEM_Get(h) in Test; right (b = true) samples without
; touching KeyLazy.Key. All state other than KeyLazy.Key is equal on both
; sides. KeyLazy.Key differs only at a tested honest handle, after Test on a
; Fresh session whose transcript is thereafter marked in TR.
; KEMReductionLazy.Key only holds keys of non-honest handles.

(define-sort Sess ()
    (Tuple8 Bool Int (Maybe Bits_lpk) (Maybe (Tuple2 Bits_lct Bits_ltag)) (Maybe Bits_ltag)
            (Maybe Int) (Maybe (Tuple2 (Maybe Int) (Maybe Int))) (Maybe Bool)))

; Session accessors. Unwrapping is only meaningful under the shape guards.
(define-fun s-role ((s Sess)) Bool (el8-1 s))
(define-fun s-kid ((s Sess)) Int (el8-2 s))
(define-fun s-pk ((s Sess)) Bits_lpk (maybe-get (el8-3 s)))
(define-fun s-c ((s Sess)) Bits_lct (el2-1 (maybe-get (el8-4 s))))
(define-fun s-t ((s Sess)) Bits_ltag (el2-2 (maybe-get (el8-4 s))))
(define-fun s-h ((s Sess)) Int (maybe-get (el2-2 (maybe-get (el8-7 s)))))
(define-fun s-hk ((s Sess)) Int (maybe-get (el2-1 (maybe-get (el8-7 s)))))
(define-fun s-k ((s Sess)) Int (maybe-get (el8-6 s)))
(define-fun s-has-m1 ((s Sess)) Bool ((_ is mk-some) (el8-3 s)))
(define-fun s-has-m2 ((s Sess)) Bool ((_ is mk-some) (el8-4 s)))
(define-fun s-accepted ((s Sess)) Bool (= (el8-8 s) (mk-some true)))
(define-fun s-tr ((s Sess)) (Tuple2 Bits_lpk (Tuple2 Bits_lct Bits_ltag))
    (mk-tuple2 (s-pk s) (maybe-get (el8-4 s))))

(define-fun msg-none ((pk Bits_lpk) (c Bits_lct)) (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))
    (mk-tuple3 pk c (as mk-none (Maybe Bits_ltag))))
(define-fun msg-some ((pk Bits_lpk) (c Bits_lct) (t Bits_ltag)) (Tuple3 Bits_lpk Bits_lct (Maybe Bits_ltag))
    (mk-tuple3 pk c (mk-some t)))

; ------------------------------------------------------------------------
; Equality of everything except KeyLazy.Key.

(define-state-relation eq-model (l r)
    (and (= l.Model4Modular.ctr_ r.Model4Modular.ctr_)
         (= l.Model4Modular.PSK r.Model4Modular.PSK)
         (= l.Model4Modular.C r.Model4Modular.C)
         (= l.Model4Modular.KID r.Model4Modular.KID)
         (= l.Model4Modular.Fresh r.Model4Modular.Fresh)
         (= l.Model4Modular.TR r.Model4Modular.TR)
         (= l.Model4Modular.State r.Model4Modular.State)
         (= l.Model4Modular.InitOf r.Model4Modular.InitOf)
         (= l.Model4Modular.RespOf r.Model4Modular.RespOf)))

(define-state-relation eq-mac (l r)
    (and (= l.MACMultiKey.kid_ctr r.MACMultiKey.kid_ctr)
         (= l.MACMultiKey.K r.MACMultiKey.K)
         (= l.MACMultiKey.C r.MACMultiKey.C)
         (= l.MACMultiKey.T r.MACMultiKey.T)))

(define-state-relation eq-kem (l r)
    (and (= l.KEMReductionLazy.hk_ctr r.KEMReductionLazy.hk_ctr)
         (= l.KEMReductionLazy.h_ctr r.KEMReductionLazy.h_ctr)
         (= l.KEMReductionLazy.PK r.KEMReductionLazy.PK)
         (= l.KEMReductionLazy.SK r.KEMReductionLazy.SK)
         (= l.KEMReductionLazy.Hon r.KEMReductionLazy.Hon)
         (= l.KEMReductionLazy.Seen r.KEMReductionLazy.Seen)
         (= l.KEMReductionLazy.HC r.KEMReductionLazy.HC)
         (= l.KEMReductionLazy.Alias r.KEMReductionLazy.Alias)
         (= l.KEMReductionLazy.Valid r.KEMReductionLazy.Valid)
         (= l.KEMReductionLazy.Key r.KEMReductionLazy.Key)
         (= l.KeyLazy.Reg r.KeyLazy.Reg)))

(define-state-relation corr-eq (l r)
    (= l.Model4Modular.C l.MACMultiKey.C))

; ------------------------------------------------------------------------
; Bounds on allocated identifiers.

(define-state-relation bound-kem (l r)
    (forall ((x Int))
        (=> (> x l.KEMReductionLazy.h_ctr)
            (and (= (select l.KEMReductionLazy.Key x) (as mk-none (Maybe Bits_lshk)))
                 (= (select l.KeyLazy.Key x) (as mk-none (Maybe Bits_lshk)))
                 (= (select r.KeyLazy.Key x) (as mk-none (Maybe Bits_lshk)))
                 (= (select l.KEMReductionLazy.Alias x) (as mk-none (Maybe Int)))
                 (= (select l.KEMReductionLazy.Valid x) (as mk-none (Maybe Tuple0)))))))

(define-state-relation bound-alias (l r)
    (forall ((x Int))
        (=> ((_ is mk-some) (select l.KEMReductionLazy.Alias x))
            (and (<= (maybe-get (select l.KEMReductionLazy.Alias x)) l.KEMReductionLazy.h_ctr)
                 ((_ is mk-some) (select l.KEMReductionLazy.Valid x))))))

(define-state-relation bound-hc (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (=> ((_ is mk-some) (select l.KEMReductionLazy.HC (mk-tuple2 pk c)))
            (<= (maybe-get (select l.KEMReductionLazy.HC (mk-tuple2 pk c))) l.KEMReductionLazy.h_ctr))))

; Honest handles are registered in KeyLazy and have no key in the reduction.
(define-state-relation hc-reg (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (let ((e (select l.KEMReductionLazy.HC (mk-tuple2 pk c))))
            (=> ((_ is mk-some) e)
                (and ((_ is mk-some) (select l.KeyLazy.Reg (maybe-get e)))
                     (= (select l.KEMReductionLazy.Key (maybe-get e)) (as mk-none (Maybe Bits_lshk))))))))

(define-state-relation bound-pk (l r)
    (forall ((y Int))
        (=> (> y l.KEMReductionLazy.hk_ctr)
            (= (select l.KEMReductionLazy.PK y) (as mk-none (Maybe Bits_lpk))))))

(define-state-relation bound-sess (l r)
    (forall ((i Int))
        (=> (> i l.Model4Modular.ctr_)
            (= (select l.Model4Modular.State i) (as mk-none (Maybe Sess))))))

(define-state-relation psk-self (l r)
    (forall ((k Int))
        (=> ((_ is mk-some) (select l.Model4Modular.PSK k))
            (= (select l.Model4Modular.PSK k) (mk-some k)))))

(define-state-relation sess-kid (l r)
    (forall ((i Int))
        (=> ((_ is mk-some) (select l.Model4Modular.State i))
            (= (select l.Model4Modular.KID i)
               (mk-some (s-kid (maybe-get (select l.Model4Modular.State i))))))))

(define-state-relation fresh-accepted (l r)
    (forall ((i Int))
        (=> ((_ is mk-some) (select l.Model4Modular.Fresh i))
            (and ((_ is mk-some) (select l.Model4Modular.State i))
                 (s-accepted (maybe-get (select l.Model4Modular.State i)))))))

; ------------------------------------------------------------------------
; Shape of responder and initiator sessions.

(define-state-relation resp-shape (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m)))
                (let ((s (maybe-get m)))
                    (let ((x (s-h s)))
                        (and (s-has-m1 s)
                             ((_ is mk-some) (el8-7 s))
                             ((_ is mk-none) (el2-1 (maybe-get (el8-7 s))))
                             ((_ is mk-some) (el2-2 (maybe-get (el8-7 s))))
                             (<= x l.KEMReductionLazy.h_ctr)
                             ((_ is mk-some) (select l.KEMReductionLazy.Valid x))
                             (= (select l.KEMReductionLazy.Alias x) (as mk-none (Maybe Int)))
                             ((_ is mk-some) (select l.KEMReductionLazy.Seen (s-pk s)))
                             (=> ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk s)))
                                 (and (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s))) (mk-some x))
                                      (= (select l.Model4Modular.RespOf (mk-tuple2 (s-pk s) (s-c s))) (mk-some i))))
                             (=> ((_ is mk-none) (select l.KEMReductionLazy.Hon (s-pk s)))
                                 ((_ is mk-some) (select l.KEMReductionLazy.Key x))))))))))

(define-state-relation resp-k (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-accepted (maybe-get m)))
                (let ((s (maybe-get m)))
                    (and (s-has-m2 s)
                         (= (el8-6 s) (el2-2 (maybe-get (el8-7 s))))))))))

(define-state-relation init-shape (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-has-m1 (maybe-get m)))
                (let ((s (maybe-get m)))
                    (and ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk s)))
                         (= (select l.Model4Modular.InitOf (s-pk s)) (mk-some i))
                         (=> (not (s-has-m2 s))
                             (and ((_ is mk-some) (el8-7 s))
                                  ((_ is mk-some) (el2-1 (maybe-get (el8-7 s))))
                                  (<= (s-hk s) l.KEMReductionLazy.hk_ctr)
                                  (= (select l.KEMReductionLazy.PK (s-hk s)) (mk-some (s-pk s)))))))))))

(define-state-relation init-m2-m1 (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-has-m2 (maybe-get m)))
                (s-has-m1 (maybe-get m))))))

(define-state-relation init-accepted (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-accepted (maybe-get m)))
                (let ((s (maybe-get m)))
                    (let ((h (s-k s)))
                        (and (s-has-m1 s)
                             (s-has-m2 s)
                             ((_ is mk-some) (el8-6 s))
                             (<= h l.KEMReductionLazy.h_ctr)
                             ((_ is mk-some) (select l.KEMReductionLazy.Valid h))
                             (or (and ((_ is mk-some) (select l.KEMReductionLazy.Alias h))
                                      (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s)))
                                         (select l.KEMReductionLazy.Alias h)))
                                 (and (= (select l.KEMReductionLazy.Alias h) (as mk-none (Maybe Int)))
                                      ((_ is mk-some) (select l.KEMReductionLazy.Key h)))))))))))

; ------------------------------------------------------------------------
; Provenance of HC entries and of the tags in the ideal MAC table.

(define-state-relation hc-prov (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (let ((e (select l.KEMReductionLazy.HC (mk-tuple2 pk c))))
            (=> ((_ is mk-some) e)
                (let ((rho (select l.Model4Modular.RespOf (mk-tuple2 pk c))))
                    (and ((_ is mk-some) (select l.KEMReductionLazy.Hon pk))
                         ((_ is mk-some) rho)
                         ((_ is mk-some) (select l.Model4Modular.State (maybe-get rho)))
                         (let ((s (maybe-get (select l.Model4Modular.State (maybe-get rho)))))
                             (and (s-role s)
                                  (s-has-m1 s)
                                  (s-has-m2 s)
                                  (= (s-pk s) pk)
                                  (= (s-c s) c)
                                  (= (s-h s) (maybe-get e))))))))))

(define-state-relation resp-unique (l r)
    (forall ((i Int) (j Int))
        (let ((mi (select l.Model4Modular.State i))
              (mj (select l.Model4Modular.State j)))
            (=> (and ((_ is mk-some) mi)
                     ((_ is mk-some) mj)
                     (s-role (maybe-get mi))
                     (s-role (maybe-get mj))
                     (s-has-m2 (maybe-get mi))
                     (s-has-m2 (maybe-get mj))
                     (= (s-h (maybe-get mi)) (s-h (maybe-get mj))))
                (= i j)))))

(define-state-relation t-none-seen (l r)
    (forall ((kid Int) (pk Bits_lpk) (c Bits_lct))
        (=> ((_ is mk-some) (select l.MACMultiKey.T (mk-tuple2 kid (msg-none pk c))))
            ((_ is mk-some) (select l.KEMReductionLazy.Seen pk)))))

(define-state-relation t-none-prov (l r)
    (forall ((kid Int) (pk Bits_lpk) (c Bits_lct))
        (let ((e (select l.MACMultiKey.T (mk-tuple2 kid (msg-none pk c)))))
            (=> (and ((_ is mk-some) e)
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon pk)))
                (let ((rho (select l.Model4Modular.RespOf (mk-tuple2 pk c))))
                    (and ((_ is mk-some) rho)
                         ((_ is mk-some) (select l.Model4Modular.State (maybe-get rho)))
                         (let ((s (maybe-get (select l.Model4Modular.State (maybe-get rho)))))
                             (and (s-role s)
                                  (= (s-kid s) kid)
                                  (s-has-m1 s)
                                  (s-has-m2 s)
                                  (= (s-pk s) pk)
                                  (= (s-c s) c)
                                  (= (s-t s) (maybe-get e))))))))))

(define-state-relation t-none-hc (l r)
    (forall ((kid Int) (pk Bits_lpk) (c Bits_lct))
        (=> (and ((_ is mk-some) (select l.MACMultiKey.T (mk-tuple2 kid (msg-none pk c))))
                 ((_ is mk-some) (select l.KEMReductionLazy.Hon pk)))
            ((_ is mk-some) (select l.KEMReductionLazy.HC (mk-tuple2 pk c))))))

(define-state-relation t-some-prov (l r)
    (forall ((kid Int) (pk Bits_lpk) (c Bits_lct) (t Bits_ltag))
        (=> ((_ is mk-some) (select l.MACMultiKey.T (mk-tuple2 kid (msg-some pk c t))))
            (let ((iof (select l.Model4Modular.InitOf pk)))
                (and ((_ is mk-some) (select l.KEMReductionLazy.Hon pk))
                     ((_ is mk-some) iof)
                     ((_ is mk-some) (select l.Model4Modular.State (maybe-get iof)))
                     (let ((s (maybe-get (select l.Model4Modular.State (maybe-get iof)))))
                         (and (not (s-role s))
                              (= (s-kid s) kid)
                              (s-has-m1 s)
                              (s-has-m2 s)
                              (= (s-pk s) pk)
                              (= (s-c s) c)
                              (= (s-t s) t))))))))

; Fresh sessions accepted while their key was uncorrupted, so the tag they
; verified is in the ideal MAC table.

(define-state-relation fresh-init-t (l r)
    (forall ((i Int))
        (=> (and ((_ is mk-some) (select l.Model4Modular.Fresh i))
                 ((_ is mk-some) (select l.Model4Modular.State i))
                 (not (s-role (maybe-get (select l.Model4Modular.State i)))))
            (let ((s (maybe-get (select l.Model4Modular.State i))))
                (= (select l.MACMultiKey.T (mk-tuple2 (s-kid s) (msg-none (s-pk s) (s-c s))))
                   (mk-some (s-t s)))))))

(define-state-relation fresh-init-alias (l r)
    (forall ((i Int))
        (=> (and ((_ is mk-some) (select l.Model4Modular.Fresh i))
                 ((_ is mk-some) (select l.Model4Modular.State i))
                 (not (s-role (maybe-get (select l.Model4Modular.State i)))))
            (let ((s (maybe-get (select l.Model4Modular.State i))))
                (and ((_ is mk-some) (select l.KEMReductionLazy.Alias (s-k s)))
                     (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s)))
                        (select l.KEMReductionLazy.Alias (s-k s))))))))

(define-state-relation fresh-resp-t (l r)
    (forall ((i Int))
        (=> (and ((_ is mk-some) (select l.Model4Modular.Fresh i))
                 ((_ is mk-some) (select l.Model4Modular.State i))
                 (s-role (maybe-get (select l.Model4Modular.State i))))
            (let ((s (maybe-get (select l.Model4Modular.State i))))
                ((_ is mk-some) (select l.MACMultiKey.T (mk-tuple2 (s-kid s) (msg-some (s-pk s) (s-c s) (s-t s)))))))))

; ------------------------------------------------------------------------
; The Key relation. Key at an honest responder's handle is equal on both
; sides, or it was tested: right is unset, left is set, TR is marked and the
; unique initiator of pk holds the same (c, t). Left's key at such a handle
; is only set once TR is marked or the initiator took a different tag.

(define-state-relation key-rel (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m))
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk (maybe-get m)))))
                (let ((s (maybe-get m)))
                    (let ((x (s-h s)) (iof (select l.Model4Modular.InitOf (s-pk s))))
                        (or (= (select l.KeyLazy.Key x) (select r.KeyLazy.Key x))
                            (and (= (select r.KeyLazy.Key x) (as mk-none (Maybe Bits_lshk)))
                                 ((_ is mk-some) (select l.KeyLazy.Key x))
                                 ((_ is mk-some) (select l.Model4Modular.TR (s-tr s)))
                                 ((_ is mk-some) iof)
                                 ((_ is mk-some) (select l.Model4Modular.State (maybe-get iof)))
                                 (let ((si (maybe-get (select l.Model4Modular.State (maybe-get iof)))))
                                     (and (s-has-m2 si)
                                          (= (s-c si) (s-c s))
                                          (= (s-t si) (s-t s))))))))))))

(define-state-relation key-unset (l r)
    (forall ((i Int))
        (let ((m (select l.Model4Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m))
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk (maybe-get m))))
                     ((_ is mk-some) (select l.KeyLazy.Key (s-h (maybe-get m)))))
                (let ((s (maybe-get m)))
                    (let ((iof (select l.Model4Modular.InitOf (s-pk s))))
                        (or ((_ is mk-some) (select l.Model4Modular.TR (s-tr s)))
                            (and ((_ is mk-some) iof)
                                 ((_ is mk-some) (select l.Model4Modular.State (maybe-get iof)))
                                 (let ((si (maybe-get (select l.Model4Modular.State (maybe-get iof)))))
                                     (and (s-has-m2 si)
                                          (= (s-c si) (s-c s))
                                          (not (= (s-t si) (s-t s)))))))))))))

; ------------------------------------------------------------------------
; Ground instances that give the solver the terms its triggers need.

(define-lemma send3-hc-instance Send3 (L R RL RR (ctr Int) (m2 (Tuple2 Bits_lct Bits_ltag)))
    (let ((st (maybe-get (select L.Model4Modular.State ctr))))
        (=> (and ((_ is mk-some) (select L.Model4Modular.State ctr))
                 (not (s-role st))
                 (s-has-m1 st)
                 ((_ is mk-some) (select L.KEMReductionLazy.Hon (s-pk st)))
                 ((_ is mk-some) (select L.MACMultiKey.T
                                     (mk-tuple2 (s-kid st) (msg-none (s-pk st) (el2-1 m2))))))
            ((_ is mk-some) (select L.KEMReductionLazy.HC (mk-tuple2 (s-pk st) (el2-1 m2)))))))

(define-fun test-guard ((m (Maybe Sess)) (fr (Maybe Tuple0)) (tr (Maybe Tuple0))) Bool
    (and ((_ is mk-some) m)
         (s-accepted (maybe-get m))
         ((_ is mk-some) fr)
         ((_ is mk-none) tr)))

; A Fresh responder: its t_I is in the table, so the unique initiator of pk
; holds the same (c, t).
(define-lemma test-resp-prov Test (L R RL RR (ctr Int))
    (let ((m (select L.Model4Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (and (test-guard m (select L.Model4Modular.Fresh ctr) (select L.Model4Modular.TR (s-tr st)))
                     (s-role st))
                (let ((tag (mk-tuple2 (s-kid st) (msg-some (s-pk st) (s-c st) (s-t st))))
                      (iof (select L.Model4Modular.InitOf (s-pk st))))
                    (and (s-has-m2 st)
                         ((_ is mk-some) (select L.MACMultiKey.T tag))
                         ((_ is mk-some) (select L.KEMReductionLazy.Hon (s-pk st)))
                         ((_ is mk-some) iof)
                         ((_ is mk-some) (select L.Model4Modular.State (maybe-get iof)))
                         (let ((si (maybe-get (select L.Model4Modular.State (maybe-get iof)))))
                             (and (s-has-m2 si) (= (s-c si) (s-c st)) (= (s-t si) (s-t st))))))))))

; A Fresh initiator: its t_R is in the table, so the responder of (pk, c) holds
; the same (c, t), and the session's handle aliases that responder's handle.
(define-lemma test-init-prov Test (L R RL RR (ctr Int))
    (let ((m (select L.Model4Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (and (test-guard m (select L.Model4Modular.Fresh ctr) (select L.Model4Modular.TR (s-tr st)))
                     (not (s-role st)))
                (let ((rho (select L.Model4Modular.RespOf (mk-tuple2 (s-pk st) (s-c st)))))
                    (and (s-has-m1 st)
                         (s-has-m2 st)
                         ((_ is mk-some) (select L.MACMultiKey.T (mk-tuple2 (s-kid st) (msg-none (s-pk st) (s-c st)))))
                         ((_ is mk-some) (select L.KEMReductionLazy.Hon (s-pk st)))
                         (= (select L.Model4Modular.InitOf (s-pk st)) (mk-some ctr))
                         ((_ is mk-some) rho)
                         ((_ is mk-some) (select L.Model4Modular.State (maybe-get rho)))
                         (let ((sr (maybe-get (select L.Model4Modular.State (maybe-get rho)))))
                             (and (s-role sr)
                                  (s-has-m1 sr)
                                  (s-has-m2 sr)
                                  (= (s-pk sr) (s-pk st))
                                  (= (s-c sr) (s-c st))
                                  (= (s-t sr) (s-t st))
                                  ((_ is mk-some) (select L.KEMReductionLazy.Alias (s-k st)))
                                  (= (select L.KEMReductionLazy.Alias (s-k st)) (mk-some (s-h sr)))))))))))

; The canonical handle of a Fresh, untested session has no key on either side.
(define-lemma test-unset Test (L R RL RR (ctr Int))
    (let ((m (select L.Model4Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model4Modular.Fresh ctr) (select L.Model4Modular.TR (s-tr st)))
                (let ((k (s-k st)))
                    (let ((canon (ite ((_ is mk-some) (select L.KEMReductionLazy.Alias k))
                                      (maybe-get (select L.KEMReductionLazy.Alias k))
                                      k)))
                        (and ((_ is mk-some) (el8-6 st))
                             ((_ is mk-some) (select L.KEMReductionLazy.Valid k))
                             ((_ is mk-some) (select L.KeyLazy.Reg canon))
                             (= (select L.KEMReductionLazy.Key canon) (as mk-none (Maybe Bits_lshk)))
                             (= (select L.KeyLazy.Key canon) (as mk-none (Maybe Bits_lshk)))
                             (= (select R.KeyLazy.Key canon) (as mk-none (Maybe Bits_lshk))))))))))

; The session owning the canonical handle: the session itself for a
; responder, its partner for an initiator.
(define-fun canon-owner ((st Sess) (ctr Int) (rho (Maybe Int))) Int
    (ite (s-role st) ctr (maybe-get rho)))

; Only the owner of the canonical handle has that handle as its responder
; handle, and the initiator of pk holds the owner's (c, t).
(define-lemma test-target Test (L R RL RR (ctr Int))
    (let ((m (select L.Model4Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model4Modular.Fresh ctr) (select L.Model4Modular.TR (s-tr st)))
                (let ((rho (select L.Model4Modular.RespOf (mk-tuple2 (s-pk st) (s-c st))))
                      (k (s-k st)))
                    (let ((canon (ite ((_ is mk-some) (select L.KEMReductionLazy.Alias k))
                                      (maybe-get (select L.KEMReductionLazy.Alias k))
                                      k))
                          (o (canon-owner st ctr rho)))
                        (and ((_ is mk-some) (select L.Model4Modular.State o))
                             (s-role (maybe-get (select L.Model4Modular.State o)))
                             (s-has-m2 (maybe-get (select L.Model4Modular.State o)))
                             (= (s-h (maybe-get (select L.Model4Modular.State o))) canon)
                             (= (s-tr (maybe-get (select L.Model4Modular.State o))) (s-tr st))
                             (forall ((i Int))
                                 (let ((mi (select L.Model4Modular.State i)))
                                     (=> (and ((_ is mk-some) mi)
                                              (s-role (maybe-get mi))
                                              (s-has-m2 (maybe-get mi))
                                              (= (s-h (maybe-get mi)) canon))
                                         (= i o)))))))))))

(define-state-relation invariant (l r)
    (and (eq-model l r) (eq-mac l r) (eq-kem l r) (corr-eq l r)
         (bound-kem l r) (bound-alias l r) (bound-hc l r) (hc-reg l r) (bound-pk l r) (bound-sess l r)
         (psk-self l r) (sess-kid l r) (fresh-accepted l r)
         (resp-shape l r) (resp-k l r) (init-shape l r) (init-m2-m1 l r) (init-accepted l r)
         (hc-prov l r) (resp-unique l r)
         (t-none-seen l r) (t-none-prov l r) (t-none-hc l r) (t-some-prov l r)
         (fresh-init-t l r) (fresh-init-alias l r) (fresh-resp-t l r)
         (key-rel l r) (key-unset l r)))

; ------------------------------------------------------------------------
; Randomness. Offsets are per oracle call.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "MACMultiKey" "MAC_Gen" "psk"))
         (= sample-id-right (sample-id "MACMultiKey" "MAC_Gen" "psk"))))

(define-fun randomness-mapping-Corrupt
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-NewSession
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send1
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMReductionLazy" "KEM_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMReductionLazy" "KEM_Gen" "kem_kgen"))))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMReductionLazy" "KEM_Encaps" "kem_encaps"))
         (= sample-id-right (sample-id "KEMReductionLazy" "KEM_Encaps" "kem_encaps"))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send4
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Reveal
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KeyLazy" "Lazy_Get" "lazy_key"))
         (= sample-id-right (sample-id "KeyLazy" "Lazy_Get" "lazy_key"))))

(define-fun randomness-mapping-Test
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KeyLazy" "Lazy_Get" "lazy_key"))
         (= sample-id-right (sample-id "Model4Modular" "Test" "test"))))

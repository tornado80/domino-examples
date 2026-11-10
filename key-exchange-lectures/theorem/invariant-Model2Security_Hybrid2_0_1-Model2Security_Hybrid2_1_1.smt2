; Hop 8 of Model2Security: Test switches from the handle key to a fresh key.
;
; Left (b = false) reads KEM_Get(h) in Test; right (b = true) samples without
; touching KeyLazy.Key. All state other than KeyLazy.Key is equal on both
; sides. KeyLazy.Key differs only at a tested honest handle, after Test on a
; Fresh initiator whose transcript is thereafter marked in TR.

(define-sort Sess ()
    (Tuple7 Bool Bits_lpk (Maybe (Tuple2 Bits_lpk Bits_lct)) (Maybe (Tuple2 Bits_lct Bits_ltag))
            (Maybe Int) (Maybe Int) (Maybe Bool)))
(define-sort Msg () (Tuple3 Bits_lpk Bits_lct Bits_lct))

; Session accessors. Unwrapping is only meaningful under the shape guards.
(define-fun s-role ((s Sess)) Bool (el7-1 s))
(define-fun s-lpk ((s Sess)) Bits_lpk (el7-2 s))
(define-fun s-pk ((s Sess)) Bits_lpk (el2-1 (maybe-get (el7-3 s))))
(define-fun s-cr ((s Sess)) Bits_lct (el2-2 (maybe-get (el7-3 s))))
(define-fun s-c ((s Sess)) Bits_lct (el2-1 (maybe-get (el7-4 s))))
(define-fun s-t ((s Sess)) Bits_ltag (el2-2 (maybe-get (el7-4 s))))
(define-fun s-k ((s Sess)) Int (maybe-get (el7-5 s)))
(define-fun s-hk ((s Sess)) Int (maybe-get (el7-6 s)))
(define-fun s-has-m1 ((s Sess)) Bool ((_ is mk-some) (el7-3 s)))
(define-fun s-has-m2 ((s Sess)) Bool ((_ is mk-some) (el7-4 s)))
(define-fun s-accepted ((s Sess)) Bool (= (el7-7 s) (mk-some true)))
(define-fun s-tr ((s Sess)) (Tuple2 (Tuple2 Bits_lpk Bits_lct) (Tuple2 Bits_lct Bits_ltag))
    (mk-tuple2 (maybe-get (el7-3 s)) (maybe-get (el7-4 s))))

; The key of the tag table for a transcript.
(define-fun tag-key ((lpk Bits_lpk) (cr Bits_lct) (pk Bits_lpk) (c Bits_lct))
    (Tuple3 Bits_lpk Bits_lct Msg)
    (mk-tuple3 lpk cr (mk-tuple3 pk cr c)))
(define-fun s-tag-key ((s Sess)) (Tuple3 Bits_lpk Bits_lct Msg)
    (tag-key (s-lpk s) (s-cr s) (s-pk s) (s-c s)))

; ------------------------------------------------------------------------
; Equality of everything except KeyLazy.Key.

(define-state-relation eq-model (l r)
    (and (= l.Model2Modular.ctr_ r.Model2Modular.ctr_)
         (= l.Model2Modular.Reg r.Model2Modular.Reg)
         (= l.Model2Modular.C r.Model2Modular.C)
         (= l.Model2Modular.Fresh r.Model2Modular.Fresh)
         (= l.Model2Modular.TR r.Model2Modular.TR)
         (= l.Model2Modular.State r.Model2Modular.State)
         (= l.Model2Modular.InitOf r.Model2Modular.InitOf)
         (= l.Model2Modular.RespOf r.Model2Modular.RespOf)))

(define-state-relation eq-lt (l r)
    (and (= l.KEMMac r.KEMMac)
         (= l.KEMReductionMac r.KEMReductionMac)))

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
    (= l.Model2Modular.C l.KEMMac.C))

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
        (=> (> i l.Model2Modular.ctr_)
            (= (select l.Model2Modular.State i) (as mk-none (Maybe Sess))))))

(define-state-relation fresh-accepted (l r)
    (forall ((i Int))
        (=> ((_ is mk-some) (select l.Model2Modular.Fresh i))
            (and ((_ is mk-some) (select l.Model2Modular.State i))
                 (s-accepted (maybe-get (select l.Model2Modular.State i)))))))

; ------------------------------------------------------------------------
; Shape of responder and initiator sessions.

(define-state-relation resp-shape (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m)))
                (let ((s (maybe-get m)))
                    (let ((x (s-k s)))
                        (and (s-has-m1 s)
                             ((_ is mk-some) (el7-5 s))
                             (<= x l.KEMReductionLazy.h_ctr)
                             ((_ is mk-some) (select l.KEMReductionLazy.Valid x))
                             (= (select l.KEMReductionLazy.Alias x) (as mk-none (Maybe Int)))
                             ((_ is mk-some) (select l.KEMReductionLazy.Seen (s-pk s)))
                             (=> ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk s)))
                                 (and (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s))) (mk-some x))
                                      (= (select l.Model2Modular.RespOf (mk-tuple2 (s-pk s) (s-c s))) (mk-some i))))
                             (=> ((_ is mk-none) (select l.KEMReductionLazy.Hon (s-pk s)))
                                 ((_ is mk-some) (select l.KEMReductionLazy.Key x))))))))))

; A responder accepts exactly when it has produced its message.
(define-state-relation resp-accepted (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-accepted (maybe-get m)))
                (s-has-m2 (maybe-get m))))))

(define-state-relation init-shape (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-has-m1 (maybe-get m)))
                (let ((s (maybe-get m)))
                    (and ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk s)))
                         (= (select l.Model2Modular.InitOf (s-pk s)) (mk-some i))
                         (=> (not (s-has-m2 s))
                             (and ((_ is mk-some) (el7-6 s))
                                  (<= (s-hk s) l.KEMReductionLazy.hk_ctr)
                                  (= (select l.KEMReductionLazy.PK (s-hk s)) (mk-some (s-pk s)))))))))))

(define-state-relation init-m2-m1 (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-has-m2 (maybe-get m)))
                (s-has-m1 (maybe-get m))))))

(define-state-relation init-accepted (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (not (s-role (maybe-get m)))
                     (s-accepted (maybe-get m)))
                (let ((s (maybe-get m)))
                    (let ((h (s-k s)))
                        (and (s-has-m1 s)
                             (s-has-m2 s)
                             ((_ is mk-some) (el7-5 s))
                             (<= h l.KEMReductionLazy.h_ctr)
                             ((_ is mk-some) (select l.KEMReductionLazy.Valid h))
                             (or (and ((_ is mk-some) (select l.KEMReductionLazy.Alias h))
                                      (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s)))
                                         (select l.KEMReductionLazy.Alias h)))
                                 (and (= (select l.KEMReductionLazy.Alias h) (as mk-none (Maybe Int)))
                                      ((_ is mk-some) (select l.KEMReductionLazy.Key h)))))))))))

; ------------------------------------------------------------------------
; Provenance of HC entries and of the tags in the ideal table.

(define-state-relation hc-prov (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (let ((e (select l.KEMReductionLazy.HC (mk-tuple2 pk c))))
            (=> ((_ is mk-some) e)
                (let ((rho (select l.Model2Modular.RespOf (mk-tuple2 pk c))))
                    (and ((_ is mk-some) (select l.KEMReductionLazy.Hon pk))
                         ((_ is mk-some) rho)
                         ((_ is mk-some) (select l.Model2Modular.State (maybe-get rho)))
                         (let ((s (maybe-get (select l.Model2Modular.State (maybe-get rho)))))
                             (and (s-role s)
                                  (s-has-m1 s)
                                  (s-has-m2 s)
                                  (= (s-pk s) pk)
                                  (= (s-c s) c)
                                  (= (s-k s) (maybe-get e))))))))))

(define-state-relation resp-unique (l r)
    (forall ((i Int) (j Int))
        (let ((mi (select l.Model2Modular.State i))
              (mj (select l.Model2Modular.State j)))
            (=> (and ((_ is mk-some) mi)
                     ((_ is mk-some) mj)
                     (s-role (maybe-get mi))
                     (s-role (maybe-get mj))
                     (s-has-m2 (maybe-get mi))
                     (s-has-m2 (maybe-get mj))
                     (= (s-k (maybe-get mi)) (s-k (maybe-get mj))))
                (= i j)))))

; These quantify over the whole key of the tag table. With c_R repeated in the
; quantified pattern, the solver did not instantiate them.
(define-sort TKey () (Tuple3 Bits_lpk Bits_lct Msg))
(define-fun k-lpk ((k TKey)) Bits_lpk (el3-1 k))
(define-fun k-cr ((k TKey)) Bits_lct (el3-2 k))
(define-fun k-pk ((k TKey)) Bits_lpk (el3-1 (el3-3 k)))
(define-fun k-mcr ((k TKey)) Bits_lct (el3-2 (el3-3 k)))
(define-fun k-c ((k TKey)) Bits_lct (el3-3 (el3-3 k)))

(define-state-relation t-seen (l r)
    (forall ((k TKey))
        (=> ((_ is mk-some) (select l.KEMMac.T k))
            ((_ is mk-some) (select l.KEMReductionLazy.Seen (k-pk k))))))

(define-state-relation t-hc (l r)
    (forall ((k TKey))
        (=> (and ((_ is mk-some) (select l.KEMMac.T k))
                 ((_ is mk-some) (select l.KEMReductionLazy.Hon (k-pk k))))
            ((_ is mk-some) (select l.KEMReductionLazy.HC (mk-tuple2 (k-pk k) (k-c k)))))))

(define-state-relation t-prov (l r)
    (forall ((k TKey))
        (let ((e (select l.KEMMac.T k)))
            (=> (and ((_ is mk-some) e)
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon (k-pk k))))
                (let ((rho (select l.Model2Modular.RespOf (mk-tuple2 (k-pk k) (k-c k)))))
                    (and ((_ is mk-some) rho)
                         ((_ is mk-some) (select l.Model2Modular.State (maybe-get rho)))
                         (let ((s (maybe-get (select l.Model2Modular.State (maybe-get rho)))))
                             (and (s-role s)
                                  (= (s-lpk s) (k-lpk k))
                                  (s-has-m1 s)
                                  (s-has-m2 s)
                                  (= (s-pk s) (k-pk k))
                                  (= (s-cr s) (k-cr k))
                                  (= (s-cr s) (k-mcr k))
                                  (= (s-c s) (k-c k))
                                  (= (s-t s) (maybe-get e))))))))))

; Fresh initiators accepted while their key was uncorrupted, so the tag they
; verified is in the ideal table.

(define-state-relation fresh-init-t (l r)
    (forall ((i Int))
        (=> (and ((_ is mk-some) (select l.Model2Modular.Fresh i))
                 ((_ is mk-some) (select l.Model2Modular.State i))
                 (not (s-role (maybe-get (select l.Model2Modular.State i)))))
            (let ((s (maybe-get (select l.Model2Modular.State i))))
                (= (select l.KEMMac.T (s-tag-key s))
                   (mk-some (s-t s)))))))

(define-state-relation fresh-init-alias (l r)
    (forall ((i Int))
        (=> (and ((_ is mk-some) (select l.Model2Modular.Fresh i))
                 ((_ is mk-some) (select l.Model2Modular.State i))
                 (not (s-role (maybe-get (select l.Model2Modular.State i)))))
            (let ((s (maybe-get (select l.Model2Modular.State i))))
                (and ((_ is mk-some) (select l.KEMReductionLazy.Alias (s-k s)))
                     (= (select l.KEMReductionLazy.HC (mk-tuple2 (s-pk s) (s-c s)))
                        (select l.KEMReductionLazy.Alias (s-k s))))))))

; ------------------------------------------------------------------------
; The Key relation. Key at an honest responder's handle is equal on both
; sides, or it was tested: right is unset, left is set, TR is marked and the
; unique initiator of pk holds the same transcript. Left's key at such a
; handle is only set once TR is marked or the initiator of pk holds the same
; ciphertext in a different transcript.

(define-state-relation key-rel (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m))
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk (maybe-get m)))))
                (let ((s (maybe-get m)))
                    (let ((x (s-k s)) (iof (select l.Model2Modular.InitOf (s-pk s))))
                        (or (= (select l.KeyLazy.Key x) (select r.KeyLazy.Key x))
                            (and (= (select r.KeyLazy.Key x) (as mk-none (Maybe Bits_lshk)))
                                 ((_ is mk-some) (select l.KeyLazy.Key x))
                                 ((_ is mk-some) (select l.Model2Modular.TR (s-tr s)))
                                 ((_ is mk-some) iof)
                                 ((_ is mk-some) (select l.Model2Modular.State (maybe-get iof)))
                                 (let ((si (maybe-get (select l.Model2Modular.State (maybe-get iof)))))
                                     (and (s-has-m2 si)
                                          (= (s-tr si) (s-tr s))))))))))))

(define-state-relation key-unset (l r)
    (forall ((i Int))
        (let ((m (select l.Model2Modular.State i)))
            (=> (and ((_ is mk-some) m)
                     (s-role (maybe-get m))
                     (s-has-m2 (maybe-get m))
                     ((_ is mk-some) (select l.KEMReductionLazy.Hon (s-pk (maybe-get m))))
                     ((_ is mk-some) (select l.KeyLazy.Key (s-k (maybe-get m)))))
                (let ((s (maybe-get m)))
                    (let ((iof (select l.Model2Modular.InitOf (s-pk s))))
                        (or ((_ is mk-some) (select l.Model2Modular.TR (s-tr s)))
                            (and ((_ is mk-some) iof)
                                 ((_ is mk-some) (select l.Model2Modular.State (maybe-get iof)))
                                 (let ((si (maybe-get (select l.Model2Modular.State (maybe-get iof)))))
                                     (and (s-has-m2 si)
                                          (= (s-c si) (s-c s))
                                          (not (= (s-tr si) (s-tr s)))))))))))))

; ------------------------------------------------------------------------
; Ground instances that give the solver the terms its triggers need.

(define-lemma send3-hc-instance Send3 (L R RL RR (ctr Int) (m2 (Tuple2 Bits_lct Bits_ltag)))
    (let ((st (maybe-get (select L.Model2Modular.State ctr))))
        (=> (and ((_ is mk-some) (select L.Model2Modular.State ctr))
                 (not (s-role st))
                 (s-has-m1 st)
                 ((_ is mk-some) (select L.KEMReductionLazy.Hon (s-pk st)))
                 ((_ is mk-some) (select L.KEMMac.T (tag-key (s-lpk st) (s-cr st) (s-pk st) (el2-1 m2)))))
            ((_ is mk-some) (select L.KEMReductionLazy.HC (mk-tuple2 (s-pk st) (el2-1 m2)))))))

(define-fun test-guard ((m (Maybe Sess)) (fr (Maybe Tuple0)) (tr (Maybe Tuple0))) Bool
    (and ((_ is mk-some) m)
         (s-accepted (maybe-get m))
         (not (s-role (maybe-get m)))
         ((_ is mk-some) fr)
         ((_ is mk-none) tr)))

; A Fresh initiator: its tag is in the table, so the responder of (pk, c) holds
; the same transcript, and the session's handle aliases that responder's handle.
(define-lemma test-init-base Test (L R RL RR (ctr Int))
    (let ((m (select L.Model2Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model2Modular.Fresh ctr) (select L.Model2Modular.TR (s-tr st)))
                (and (s-has-m1 st)
                     (s-has-m2 st)
                     (= (select L.KEMMac.T (s-tag-key st)) (mk-some (s-t st)))
                     ((_ is mk-some) (select L.KEMReductionLazy.Hon (s-pk st)))
                     (= (select L.Model2Modular.InitOf (s-pk st)) (mk-some ctr)))))))

(define-lemma test-init-rho Test (L R RL RR (ctr Int))
    (let ((m (select L.Model2Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model2Modular.Fresh ctr) (select L.Model2Modular.TR (s-tr st)))
                (let ((rho (select L.Model2Modular.RespOf (mk-tuple2 (s-pk st) (s-c st)))))
                    (and ((_ is mk-some) rho)
                         ((_ is mk-some) (select L.Model2Modular.State (maybe-get rho)))
                         (let ((sr (maybe-get (select L.Model2Modular.State (maybe-get rho)))))
                             (and (s-role sr)
                                  (= (s-lpk sr) (s-lpk st))
                                  (s-has-m1 sr)
                                  (s-has-m2 sr)
                                  (= (s-pk sr) (s-pk st))
                                  (= (s-cr sr) (s-cr st))
                                  (= (s-c sr) (s-c st))
                                  (= (s-t sr) (s-t st))))))))))

(define-lemma test-init-prov Test (L R RL RR (ctr Int))
    (let ((m (select L.Model2Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model2Modular.Fresh ctr) (select L.Model2Modular.TR (s-tr st)))
                (let ((rho (select L.Model2Modular.RespOf (mk-tuple2 (s-pk st) (s-c st)))))
                    (let ((sr (maybe-get (select L.Model2Modular.State (maybe-get rho)))))
                        (and (= (s-tr sr) (s-tr st))
                             ((_ is mk-some) (select L.KEMReductionLazy.Alias (s-k st)))
                             (= (select L.KEMReductionLazy.Alias (s-k st)) (mk-some (s-k sr))))))))))

; The canonical handle of a Fresh, untested initiator has no key on either side.
(define-lemma test-unset Test (L R RL RR (ctr Int))
    (let ((m (select L.Model2Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model2Modular.Fresh ctr) (select L.Model2Modular.TR (s-tr st)))
                (let ((k (s-k st)))
                    (let ((canon (maybe-get (select L.KEMReductionLazy.Alias k))))
                        (and ((_ is mk-some) (el7-5 st))
                             ((_ is mk-some) (select L.KEMReductionLazy.Valid k))
                             ((_ is mk-some) (select L.KEMReductionLazy.Alias k))
                             ((_ is mk-some) (select L.KeyLazy.Reg canon))
                             (= (select L.KEMReductionLazy.Key canon) (as mk-none (Maybe Bits_lshk)))
                             (= (select L.KeyLazy.Key canon) (as mk-none (Maybe Bits_lshk)))
                             (= (select R.KeyLazy.Key canon) (as mk-none (Maybe Bits_lshk))))))))))

; Only the partner responder has the canonical handle as its handle.
(define-lemma test-target Test (L R RL RR (ctr Int))
    (let ((m (select L.Model2Modular.State ctr)))
        (let ((st (maybe-get m)))
            (=> (test-guard m (select L.Model2Modular.Fresh ctr) (select L.Model2Modular.TR (s-tr st)))
                (let ((o (maybe-get (select L.Model2Modular.RespOf (mk-tuple2 (s-pk st) (s-c st)))))
                      (canon (maybe-get (select L.KEMReductionLazy.Alias (s-k st)))))
                    (and ((_ is mk-some) (select L.Model2Modular.State o))
                         (s-role (maybe-get (select L.Model2Modular.State o)))
                         (s-has-m2 (maybe-get (select L.Model2Modular.State o)))
                         (= (s-k (maybe-get (select L.Model2Modular.State o))) canon)
                         (= (s-tr (maybe-get (select L.Model2Modular.State o))) (s-tr st))
                         (forall ((i Int))
                             (let ((mi (select L.Model2Modular.State i)))
                                 (=> (and ((_ is mk-some) mi)
                                          (s-role (maybe-get mi))
                                          (s-has-m2 (maybe-get mi))
                                          (= (s-k (maybe-get mi)) canon))
                                     (= i o))))))))))

(define-state-relation invariant (l r)
    (and (eq-model l r) (eq-lt l r) (eq-kem l r) (corr-eq l r)
         (bound-kem l r) (bound-alias l r) (bound-hc l r) (hc-reg l r) (bound-pk l r) (bound-sess l r)
         (fresh-accepted l r)
         (resp-shape l r) (resp-accepted l r) (init-shape l r) (init-m2-m1 l r) (init-accepted l r)
         (hc-prov l r) (resp-unique l r)
         (t-seen l r) (t-hc l r) (t-prov l r)
         (fresh-init-t l r) (fresh-init-alias l r)
         (key-rel l r) (key-unset l r)))

; ------------------------------------------------------------------------
; Randomness. Offsets are per oracle call.

(define-fun same-sample ((sample-id-left SampleId) (sample-id-right SampleId) (id SampleId)) Bool
    (and (= sample-id-left id) (= sample-id-right id)))

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (same-sample sample-id-left sample-id-right (sample-id "KEMMac" "KM_Gen" "kem_kgen"))))

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
         (or (same-sample sample-id-left sample-id-right (sample-id "KEMReductionLazy" "KEM_Gen" "kem_kgen"))
             (same-sample sample-id-left sample-id-right (sample-id "KEMMac" "KM_Encaps" "kem_encaps")))))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (same-sample sample-id-left sample-id-right (sample-id "KEMReductionLazy" "KEM_Encaps" "kem_encaps"))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Reveal
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (same-sample sample-id-left sample-id-right (sample-id "KeyLazy" "Lazy_Get" "lazy_key"))))

(define-fun randomness-mapping-Test
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KeyLazy" "Lazy_Get" "lazy_key"))
         (= sample-id-right (sample-id "Model2Modular" "Test" "test"))))

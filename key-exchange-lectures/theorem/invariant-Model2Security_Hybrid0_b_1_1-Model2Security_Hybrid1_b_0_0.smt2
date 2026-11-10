;; Hop 3: Model2Security_Hybrid0_b_1_1 == Model2Security_Hybrid1_b_0_0.
;; The left sessions hold sk, shk_R, sk_fs and the session key. The right
;; sessions hold handles, and the values live in KEMMac and KEMIndCca. The
;; collision aborts stop an entry in those tables from being overwritten.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMCollisions_lt" "Coll_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMMac" "KM_Gen" "kem_kgen"))))

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
         (or (and (= sample-id-left (sample-id "KEMCollisions_eph" "Coll_Gen" "kem_kgen"))
                  (= sample-id-right (sample-id "KEMIndCca" "Ind_Gen" "kem_kgen")))
             (and (= sample-id-left (sample-id "KEMCollisions_lt" "Coll_Encaps" "kem_encaps"))
                  (= sample-id-right (sample-id "KEMMac" "KM_Encaps" "kem_encaps"))))))

(define-state-relation send2-pk-honest (l r)
    ((_ is mk-some) (select r.KEMReductionIndCca.Hon (el2-1 <arg-Model2Security_Hybrid1-Send2-m1>))))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMCollisions_eph" "Coll_Encaps" "kem_encaps"))
         (ite (send2-pk-honest <<game-state-Model2Security_Hybrid0_b_1_1-old>> <<game-state-Model2Security_Hybrid1_b_0_0-old>>)
              (= sample-id-right (sample-id "KEMIndCca" "Ind_Encaps" "kem_encaps"))
              (= sample-id-right (sample-id "KEMReductionIndCca" "KEM_Encaps" "kem_encaps")))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Reveal
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Test
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "Model2" "Test" "test"))
         (= sample-id-right (sample-id "Model2Modular" "Test" "test"))))

;; Counters and the tables that are copied literally.
(define-state-relation tables-equal (l r)
    (and (= l.Model2.ctr_ r.Model2Modular.ctr_)
         (= l.Model2.C r.Model2Modular.C)
         (= l.Model2.C r.KEMMac.C)
         (= l.Model2.Fresh r.Model2Modular.Fresh)
         (= l.Model2.TR r.Model2Modular.TR)
         (= l.Model2.SK r.KEMMac.SK)
         (= l.KEMCollisions_lt.Hon r.KEMReductionMac.Hon)
         (= l.KEMCollisions_lt.UsedCt r.KEMReductionMac.HC)
         (= l.KEMCollisions_eph.Hon r.KEMReductionIndCca.Hon)
         (= l.KEMCollisions_eph.UsedCt r.KEMReductionIndCca.HC)))

;; Long-term keys: registered, honest and used are all the generated ones.
(define-state-relation lt-registered (l r)
    (forall ((pk Bits_lpk))
        (and (= ((_ is mk-some) (select r.Model2Modular.Reg pk))
                ((_ is mk-some) (select r.KEMMac.SK pk)))
             (= ((_ is mk-some) (select r.KEMReductionMac.Hon pk))
                ((_ is mk-some) (select r.KEMMac.SK pk)))
             (= ((_ is mk-some) (select l.KEMCollisions_lt.UsedPk pk))
                ((_ is mk-some) (select r.KEMMac.SK pk))))))

(define-state-relation lt-shared (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (= ((_ is mk-some) (select r.KEMReductionMac.HC (mk-tuple2 pk c)))
           ((_ is mk-some) (select r.KEMMac.S (mk-tuple2 pk c))))))

;; Ephemeral keys.
(define-state-relation eph-used-pk (l r)
    (forall ((pk Bits_lpk))
        (= ((_ is mk-some) (select l.KEMCollisions_eph.UsedPk pk))
           (or ((_ is mk-some) (select r.KEMReductionIndCca.Hon pk))
               ((_ is mk-some) (select r.KEMReductionIndCca.Seen pk))))))

(define-state-relation eph-hon-has-sk (l r)
    (forall ((pk Bits_lpk))
        (=> ((_ is mk-some) (select r.KEMReductionIndCca.Hon pk))
            ((_ is mk-some) (select r.KEMIndCca.SK pk)))))

(define-state-relation eph-pk-table (l r)
    (forall ((hk Int))
        (let ((p (select r.KEMReductionIndCca.PK hk)))
            (and (=> (> hk r.KEMReductionIndCca.hk_ctr) ((_ is mk-none) p))
                 (=> ((_ is mk-some) p)
                     ((_ is mk-some) (select r.KEMReductionIndCca.Hon (maybe-get p))))))))

(define-state-relation handle-bound (l r)
    (forall ((h Int))
        (=> (> h r.KEMReductionIndCca.h_ctr)
            (and ((_ is mk-none) (select r.KEMReductionIndCca.Key h))
                 ((_ is mk-none) (select r.KEMReductionIndCca.Valid h))))))

(define-state-relation session-bound (l r)
    (forall ((ctr Int))
        (=> (> ctr r.Model2Modular.ctr_)
            (and ((_ is mk-none) (select l.Model2.State ctr))
                 ((_ is mk-none) (select r.Model2Modular.State ctr))))))

;; Sessions, field by field.
(define-state-relation sessions-related (l r)
    (forall ((ctr Int))
        (let ((sl (select l.Model2.State ctr))
              (sr (select r.Model2Modular.State ctr)))
            (and
                (= ((_ is mk-none) sl) ((_ is mk-none) sr))
                (=> ((_ is mk-some) sl)
                    (let ((tl (maybe-get sl))
                          (tr (maybe-get sr)))
                        (let ((role (el8-1 tl))
                              (pk (el8-2 tl))
                              (sk (el8-3 tl))
                              (m1 (el8-4 tl))
                              (m2 (el8-5 tl))
                              (k (el8-6 tl))
                              (other (el8-7 tl))
                              (acc (el8-8 tl))
                              (kh (el7-5 tr))
                              (hk (el7-6 tr)))
                            (and
                                (= role (el7-1 tr))
                                (= pk (el7-2 tr))
                                (= m1 (el7-3 tr))
                                (= m2 (el7-4 tr))
                                (= acc (el7-7 tr))
                                ((_ is mk-some) (select r.KEMMac.SK pk))
                                (=> (not role) ((_ is mk-none) sk))
                                (=> role (= sk (select r.KEMMac.SK pk)))
                                (= ((_ is mk-none) k) ((_ is mk-none) kh))
                                (=> ((_ is mk-some) k)
                                    (and ((_ is mk-some) (select r.KEMReductionIndCca.Valid (maybe-get kh)))
                                         (= (select r.KEMReductionIndCca.Key (maybe-get kh)) k)))
                                (=> (and (not role) ((_ is mk-some) m1))
                                    (let ((pkfs (el2-1 (maybe-get m1)))
                                          (cR (el2-2 (maybe-get m1)))
                                          (skfs (el2-1 (maybe-get other)))
                                          (shkR (el2-2 (maybe-get other))))
                                        (and ((_ is mk-some) other)
                                             ((_ is mk-some) (select r.KEMReductionMac.HC (mk-tuple2 pk cR)))
                                             (= (select r.KEMMac.S (mk-tuple2 pk cR)) (mk-some shkR))
                                             (= ((_ is mk-none) skfs) ((_ is mk-none) hk))
                                             (=> ((_ is mk-none) m2) ((_ is mk-some) skfs))
                                             (=> ((_ is mk-some) skfs)
                                                 (and (= (select r.KEMReductionIndCca.PK (maybe-get hk)) (mk-some pkfs))
                                                      ((_ is mk-some) (select r.KEMReductionIndCca.Hon pkfs))
                                                      (= (select r.KEMIndCca.SK pkfs) skfs))))))))))))))

(define-state-relation invariant (l r)
    (and (tables-equal l r)
         (lt-registered l r)
         (lt-shared l r)
         (eph-used-pk l r)
         (eph-hon-has-sk l r)
         (eph-pk-table l r)
         (handle-bound l r)
         (session-bound l r)
         (sessions-related l r)))

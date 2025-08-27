package com.bookshop.repository;

import com.bookshop.model.MFAToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

 // Validate token 
public interface MFATokenRepository extends JpaRepository<MFAToken, Long> {

    @Query("SELECT t FROM MFAToken t WHERE t.user.id = :userId " +
            "AND t.used = false AND t.expiresAt > :now " +
            "ORDER BY t.createdAt DESC")
    Optional<MFAToken> findLatestValidToken(@Param("userId") Long userId,
                                            @Param("now") LocalDateTime now);

    default Optional<MFAToken> findLatestValidToken(Long userId) {
        return findLatestValidToken(userId, LocalDateTime.now());
    }

    @Modifying
    @Transactional
    @Query("UPDATE MFAToken t SET t.used = true WHERE t.user.id = :userId AND t.used = false")
    int invalidateUserTokens(@Param("userId") Long userId);

    @Modifying
    @Transactional
    @Query("DELETE FROM MFAToken t WHERE t.expiresAt < :cutoff")
    int deleteExpiredTokens(@Param("cutoff") LocalDateTime cutoff);

    @Query("SELECT COUNT(t) FROM MFAToken t WHERE t.user.id = :userId " +
            "AND t.createdAt > :since AND t.used = false")
    long countRecentTokens(@Param("userId") Long userId, @Param("since") LocalDateTime since);

}

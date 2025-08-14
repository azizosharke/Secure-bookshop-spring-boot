package com.bookshop.repository;

import com.bookshop.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {

    Optional<UserSession> findBySessionId(String sessionId);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.active = true")
    List<UserSession> findActiveSessionsByUserId(@Param("userId") Long userId);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId AND s.active = true " +
            "AND s.lastAccessedAt > :since")
    List<UserSession> findRecentActiveSessionsByUserId(@Param("userId") Long userId,
                                                       @Param("since") LocalDateTime since);

    @Query("SELECT COUNT(s) FROM UserSession s WHERE s.user.id = :userId AND s.active = true")
    long countActiveSessionsByUserId(@Param("userId") Long userId);

    @Query("SELECT s FROM UserSession s WHERE s.ipAddress = :ipAddress AND s.active = true")
    List<UserSession> findActiveSessionsByIpAddress(@Param("ipAddress") String ipAddress);

    @Modifying
    @Transactional
    @Query("UPDATE UserSession s SET s.active = false, s.invalidatedAt = :now " +
            "WHERE s.user.id = :userId AND s.active = true")
    int invalidateUserSessions(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("UPDATE UserSession s SET s.active = false, s.invalidatedAt = :now " +
            "WHERE s.sessionId = :sessionId")
    int invalidateSession(@Param("sessionId") String sessionId, @Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("DELETE FROM UserSession s WHERE s.active = false AND s.invalidatedAt < :cutoff")
    int deleteInactiveSessions(@Param("cutoff") LocalDateTime cutoff);

    @Modifying
    @Transactional
    @Query("UPDATE UserSession s SET s.active = false, s.invalidatedAt = :now " +
            "WHERE s.active = true AND s.lastAccessedAt < :cutoff")
    int invalidateExpiredSessions(@Param("cutoff") LocalDateTime cutoff,
                                  @Param("now") LocalDateTime now);

    @Query("SELECT s FROM UserSession s WHERE s.securityFlags > 0 AND s.active = true")
    List<UserSession> findSessionsWithSecurityFlags();

    @Query("SELECT DISTINCT s.ipAddress FROM UserSession s WHERE s.user.id = :userId " +
            "AND s.createdAt > :since")
    List<String> findRecentIpAddressesByUserId(@Param("userId") Long userId,
                                               @Param("since") LocalDateTime since);

    @Query("SELECT s FROM UserSession s WHERE s.user.id = :userId " +
            "ORDER BY s.createdAt DESC")
    List<UserSession> findSessionHistoryByUserId(@Param("userId") Long userId);
}
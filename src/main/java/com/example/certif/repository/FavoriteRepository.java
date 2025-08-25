package com.example.certif.repository;

import com.example.certif.entity.Favorite;
import com.example.certif.entity.id.FavoriteId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FavoriteRepository extends JpaRepository<Favorite, FavoriteId> {
    // 특정 사용자의 즐겨찾기 목록 조회
    List<Favorite> findByUserId(Long userId);

    // 특정 사용자, 해당 자격증을 즐겨찾기 했는지 확인
    boolean existsByUserIdAndCertificateId(Long userId, Long certificateId);

    // 즐겨찾기 해제
    long deleteByUserIdAndCertificateId(Long userId, Long certificateId);
}


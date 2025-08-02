package com.example.certif.repository;

import com.example.certif.entity.StudyPost;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface StudyPostRepository extends JpaRepository<StudyPost, Long> {

    // 카테고리별 최신순 정렬
    List<StudyPost> findByCategoryIdOrderByCreatedAtDesc(Long categoryId);

    // 게시글 ID로 조회
    Optional<StudyPost> findByPostId(Long postId);
}

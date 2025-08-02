package com.example.certif.service;

import com.example.certif.dto.StudyPostDto;
import com.example.certif.dto.StudyPostResponseDto;
import com.example.certif.dto.StudyPostUpdateDto;
import com.example.certif.entity.StudyPost;
import com.example.certif.repository.StudyPostRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class StudyPostService {

    @Autowired
    private StudyPostRepository studyPostRepository;
    @Autowired
    private CategoryRepository categoryRepository;
    @Autowired
    private UserRepository userRepository;

    // 1-1. 스터디 게시판 전체 글 조회 by 카테고리에서 기본 화면 (카테고리 번호=1)
    public List<StudyPostResponseDto> getDefaultCategoryPosts() {
        // 1. 글조회
        List<StudyPost> posts = studyPostRepository.findByCategoryIdOrderByCreatedAtDesc(1);
        // 2. 엔티티 -> DTO 변환
        List<StudyPostResponseDto> dtos = new ArrayList<>();
        for (int i = 0; i < posts.size(); i++) {
            StudyPost p = posts.get(i);
            StudyPostResponseDto dto = StudyPostResponseDto.createStudyPostDto(p);
            dtos.add(dto);
        }
        // 3. 결과 반환
        return dtos;
    }


    // 1-2. 스터디 게시판 전체 글 조회 by 카테고리
    public List<StudyPostResponseDto> getPostsByCategory(Long categoryId) {
        // 1. 글조회
        List<StudyPost> posts = studyPostRepository.findByCategoryIdOrderByCreatedAtDesc(categoryId);
        // 2. 엔티티 -> DTO 변환
        List<StudyPostResponseDto> dtos = new ArrayList<>();
        for (int i = 0; i < posts.size(); i++) {
            StudyPost p = posts.get(i);
            StudyPostResponseDto dto = StudyPostResponseDto.createStudyPostDto(p);
            dtos.add(dto);
        }
        // 3. 결과 반환
        return dtos;
    }


    // 1-3. 특정 스터디 게시판 글 조회
    public StudyPostResponseDto findById(Long postId) {
        StudyPost post = studyPostRepository.findByPostId(postId)
                .orElseThrow(() -> new IllegalArgumentException("해당 게시글이 존재하지 않습니다. postId=" + postId));
        return StudyPostResponseDto.createStudyPostDto(post);
    }
   

    // 2. 스터디 게시판 글 생성
    @Transactional
    public StudyPostResponseDto create(StudyPostDto dto, User user) {
        // 1. 카테고리 조회
        Category category = categoryRepository.findById(dto.getCategoryId())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 카테고리"));
        // 2. 게시판 글 엔티티 생성
        StudyPost studypost = StudyPost.createStudyPost(dto, user, category);
        // 3. 저장
        StudyPost created = studyPostRepository.save(studypost);
        // 4. 반환
        return StudyPostResponseDto.createStudyPostDto(created);
    }


    // 3. 스터디 게시판 글 수정
    @Transactional
    public StudyPostResponseDto update(Long postId, StudyPostUpdateDto dto, User user) {
        // 1. 게시판 글 조회 및 예외 발생
        StudyPost target = studyPostRepository.findByPostId(postId)
                .orElseThrow(() -> new IllegalArgumentException("스터디 게시판 글 수정 실패!" + "대상 게시판 글이 없습니다."));
        // 2. 권한 체크 - 로그인한 사용자와 게시글 작성자가 같은지 확인
        if (!target.getUser().getId().equals(user.getId())) {
            throw new AccessDeniedException("수정 권한이 없습니다.");
        }
        // 3. 게시판 글 수정
        target.patch(dto);
        // 4. DB로 갱신
        StudyPost updated = studyPostRepository.save(target);
        // 5. 게시판 글 엔티티를 DTO로 변환 및 반환
        return StudyPostResponseDto.createStudyPostDto(updated);
    }


    // 4. 스터디 게시판 글 삭제
    @Transactional
    public void delete(Long postId) {
        // 1. 게시판 글 조회 및 예외 발생
        StudyPost target = studyPostRepository.findByPostId(postId)
                .orElseThrow(() -> new IllegalArgumentException("게시판 글 삭제 실패! " +
                        "대상이 없습니다."));
        // 2. 삭제 권한 확인
        if (!target.getUser().getId().equals(user.getId())) {
            throw new AccessDeniedException("삭제 권한이 없습니다.");
        }
        // 3. 게시판 글 삭제
        studyPostRepository.delete(target);
    }

}
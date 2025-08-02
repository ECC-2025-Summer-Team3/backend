import com.example.certif.dto.StudyPostDto;
import com.example.certif.dto.StudyPostResponseDto;
import com.example.certif.dto.StudyPostUpdateDto;
import com.example.certif.service.StudyPostService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.graphql.GraphQlProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// StudyPostController.java
@RestController
@RequestMapping("/api/study")
@RequiredArgsConstructor

public class StudyPostController {
    @Autowired
    private StudyPostService studyPostService;

    // 1-1. 스터디 게시판 전체 글 조회 by 카테고리에서 기본 화면 (카테고리 번호=1)
    @GetMapping("/default")
    public ResponseEntity<List<StudyPostResponseDto>> defaultposts() {
        // 서비스에 위임
        List<StudyPostDto> dtos = studyPostService.getDefaultCategoryPosts(1);
        // 결과 응답
        return ResponseEntity.status(HttpStatus.OK).body(dtos);
    }


    // 1-2. 스터디 게시판 전체 글 조회 by 카테고리
    @GetMapping("/category/{categoryId}")
    public ResponseEntity<List<StudyPostResponseDto>> posts(@PathVariable Long categoryId){
        // 서비스에 위임
        List<StudyPostDto> dtos = studyPostService.getPostsByCategory(categoryId);
        // 결과 응답
        return ResponseEntity.status(HttpStatus.OK).body(dtos);
    }


    // 1-3. 특정 스터디 게시판 글 조회
    @GetMapping("/{postId}")
    public ResponseEntity<StudyPostResponseDto> getPost(@PathVariable Long postId) {
        // 서비스에 위임
        StudyPostResponseDto dto = studyPostService.findById(postId);
        // 결과 응답
        return ResponseEntity.status(HttpStatus.OK).body(dto);
    }



    //  2. 스터디 게시판 글 생성
    @PostMapping
    public ResponseEntity<StudyPostResponseDto> create(@RequestBody StudyPostDto dto,
                                                       @AuthenticationPrincipal User user) {
        // 서비스에 위임
        StudyPostDto createdDto = studyPostService.create(dto, user);
        // 결과 응답
        return ResponseEntity.status(HttpStatus.OK).body(createdDto);
    }


    // 3. 스터디 게시판 글 수정
    @PatchMapping("/{postId}")
    public ResponseEntity<StudyPostResponseDto> update(@PathVariable Long postId,
                                                       @RequestBody StudyPostUpdateDto dto,
                                                       @AuthenticationPrincipal User user){
        // 서비스에 위임
        StudyPostResponseDto updatedDto = studyPostService.update(postId, dto, user);
        // 결과 응답
        return ResponseEntity.status(HttpStatus.OK).body(updatedDto);
    }


    // 4. 스터디 게시판 글 삭제
    @DeleteMapping("/{postId}")
    public ResponseEntity<Void> deletePost(@PathVariable Long postId,
                                                         @AuthenticationPrincipal User user) {
        studyPostService.delete(postId, user); // 작성자 확인 포함
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

}
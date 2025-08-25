package com.example.certif.service;

import com.example.certif.dto.FavoriteCertificateDto;
import com.example.certif.entity.Certificate;
import com.example.certif.entity.Favorite;
import com.example.certif.entity.User;
import com.example.certif.entity.id.FavoriteId;
import com.example.certif.repository.CertificateRepository;
import com.example.certif.repository.FavoriteRepository;
import com.example.certif.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class FavoriteService {

    private final FavoriteRepository favoriteRepository;
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;

    // 1. 사용자의 즐겨찾기 자격증 목록 조회
    @Transactional
    public List<FavoriteCertificateDto> getFavoritesByUser(Long userId) {
        List<Favorite> favorites = favoriteRepository.findByUserId(userId);
        return favorites.stream()
                .map(fav -> new FavoriteCertificateDto(
                        fav.getCertificate().getId(),
                        fav.getCertificate().getName(),
                        fav.getCertificate().getCategory().getId(),
                        fav.getCertificate().getCategory().getName()
                ))
                .collect(Collectors.toList());
    }

    // 2. 자격증을 즐겨찾기에 등록
    @Transactional
    public void addFavorite(Long userId, Long certificateId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("유저를 찾을 수 없습니다."));
        Certificate certificate = certificateRepository.findById(certificateId)
                .orElseThrow(() -> new IllegalArgumentException("자격증을 찾을 수 없습니다."));

        FavoriteId id = new FavoriteId(userId, certificateId);
        // 이미 등록된 즐겨찾기인지 체크
        if (favoriteRepository.existsByUserIdAndCertificateId(userId, certificateId)) {
            throw new IllegalArgumentException("이미 즐겨찾기에 등록된 자격증입니다.");
        }

        Favorite favorite = new Favorite(id, certificate, user);
        favoriteRepository.save(favorite);
    }

    // 3. 자격증을 즐겨찾기에서 해제
    @Transactional
    public void removeFavorite(Long userId, Long certificateId) {
// 삭제 전 존재 여부 확인
        long deletedCount = favoriteRepository.deleteByUserIdAndCertificateId(userId, certificateId);

        if(deletedCount == 0){
            throw new RuntimeException("해당 즐겨찾기가 존재하지 않습니다.");
        }
        favoriteRepository.deleteByUserIdAndCertificateId(userId, certificateId);
        favoriteRepository.flush(); // 트랜잭션 내 즉시 DB 반영
        }
}





"""
자동 패치 적용 및 PR 생성 모듈
LLM이 제안한 패치를 git에 적용하고 GitHub PR을 생성
"""

import logging
import subprocess
import tempfile
import os
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import json

from .sast_dast_schema import SecurityFinding, Severity
from ..llm.patch_generator import PatchProposal

logger = logging.getLogger(__name__)

class PatchApplier:
    """패치 자동 적용 및 PR 생성기"""
    
    def __init__(self, 
                 repo_path: str,
                 github_token: Optional[str] = None,
                 auto_pr_threshold: Severity = Severity.HIGH):
        self.repo_path = Path(repo_path).resolve()
        self.github_token = github_token
        self.auto_pr_threshold = auto_pr_threshold
        
        # git 명령어 실행을 위한 환경 설정
        self.env = os.environ.copy()
        if github_token:
            self.env['GITHUB_TOKEN'] = github_token
    
    def apply_patch(self, patch: PatchProposal, code_snippet: Optional[str] = None) -> Dict[str, Any]:
        """
        패치를 적용하고 결과 반환
        
        Args:
            patch: 적용할 패치 제안
            code_snippet: 원본 코드 스니펫 (가능시)
            
        Returns:
            적용 결과
        """
        try:
            # 1. 현재 git 상태 확인
            current_branch = self._get_current_branch()
            if not current_branch:
                return {"success": False, "error": "Git 저장소가 아닙니다"}
            
            # 2. 새로운 보안 수정 브랜치 생성
            branch_name = f"secfix/{patch.finding_id}"
            if not self._create_branch(branch_name):
                return {"success": False, "error": "브랜치 생성 실패"}
            
            # 3. 패치 적용
            if patch.diff:
                apply_result = self._apply_diff(patch.diff)
                if not apply_result["success"]:
                    return apply_result
            
            # 4. 변경사항 커밋
            commit_result = self._commit_changes(patch)
            if not commit_result["success"]:
                return commit_result
            
            # 5. 브랜치 푸시
            push_result = self._push_branch(branch_name)
            if not push_result["success"]:
                return push_result
            
            # 6. PR 생성 여부 결정
            should_create_pr = self._should_create_pr(patch)
            
            result = {
                "success": True,
                "branch_name": branch_name,
                "commit_hash": commit_result.get("commit_hash"),
                "should_create_pr": should_create_pr,
                "patch_applied": bool(patch.diff),
                "message": "패치가 성공적으로 적용되었습니다"
            }
            
            # 7. 자동 PR 생성 (고위험 취약점)
            if should_create_pr and self.github_token:
                pr_result = self._create_pull_request(patch, branch_name)
                result["pr_created"] = pr_result["success"]
                result["pr_url"] = pr_result.get("pr_url")
                result["pr_number"] = pr_result.get("pr_number")
            
            return result
            
        except Exception as e:
            logger.error(f"패치 적용 중 오류: {e}")
            return {"success": False, "error": str(e)}
    
    def _get_current_branch(self) -> Optional[str]:
        """현재 git 브랜치 이름 반환"""
        try:
            result = subprocess.run(
                ["git", "branch", "--show-current"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                env=self.env
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.error(f"현재 브랜치 확인 실패: {e}")
        return None
    
    def _create_branch(self, branch_name: str) -> bool:
        """새로운 브랜치 생성"""
        try:
            # 브랜치가 이미 존재하는지 확인
            result = subprocess.run(
                ["git", "show-ref", "--verify", f"refs/heads/{branch_name}"],
                cwd=self.repo_path,
                capture_output=True,
                env=self.env
            )
            
            if result.returncode == 0:
                # 브랜치가 이미 존재하면 체크아웃
                result = subprocess.run(
                    ["git", "checkout", branch_name],
                    cwd=self.repo_path,
                    env=self.env
                )
            else:
                # 새 브랜치 생성 및 체크아웃
                result = subprocess.run(
                    ["git", "checkout", "-b", branch_name],
                    cwd=self.repo_path,
                    env=self.env
                )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"브랜치 생성 실패: {e}")
            return False
    
    def _apply_diff(self, diff_content: str) -> Dict[str, Any]:
        """diff 내용을 파일에 적용"""
        try:
            # 임시 파일에 diff 저장
            with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
                f.write(diff_content)
                temp_patch = f.name
            
            # git apply로 패치 적용
            result = subprocess.run(
                ["git", "apply", temp_patch],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                env=self.env
            )
            
            # 임시 파일 삭제
            os.unlink(temp_patch)
            
            if result.returncode == 0:
                return {"success": True, "message": "패치가 성공적으로 적용되었습니다"}
            else:
                return {
                    "success": False, 
                    "error": f"패치 적용 실패: {result.stderr}",
                    "stderr": result.stderr
                }
                
        except Exception as e:
            logger.error(f"패치 적용 실패: {e}")
            return {"success": False, "error": str(e)}
    
    def _commit_changes(self, patch: PatchProposal) -> Dict[str, Any]:
        """변경사항을 커밋"""
        try:
            # 변경된 파일 확인
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                env=self.env
            )
            
            if result.returncode != 0:
                return {"success": False, "error": "git status 확인 실패"}
            
            changed_files = result.stdout.strip().split('\n') if result.stdout.strip() else []
            if not changed_files:
                return {"success": False, "error": "커밋할 변경사항이 없습니다"}
            
            # 변경된 파일들을 스테이징
            for line in changed_files:
                if line.strip():
                    file_path = line[3:]  # git status --porcelain 형식: " M filename"
                    subprocess.run(
                        ["git", "add", file_path],
                        cwd=self.repo_path,
                        env=self.env
                    )
            
            # 커밋 생성
            commit_result = subprocess.run(
                ["git", "commit", "-m", patch.commit_message, "-m", patch.commit_body],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                env=self.env
            )
            
            if commit_result.returncode == 0:
                # 커밋 해시 가져오기
                hash_result = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True,
                    env=self.env
                )
                
                commit_hash = hash_result.stdout.strip() if hash_result.returncode == 0 else None
                
                return {
                    "success": True,
                    "message": "커밋이 성공적으로 생성되었습니다",
                    "commit_hash": commit_hash
                }
            else:
                return {
                    "success": False,
                    "error": f"커밋 생성 실패: {commit_result.stderr}",
                    "stderr": commit_result.stderr
                }
                
        except Exception as e:
            logger.error(f"커밋 생성 실패: {e}")
            return {"success": False, "error": str(e)}
    
    def _push_branch(self, branch_name: str) -> Dict[str, Any]:
        """브랜치를 원격 저장소에 푸시"""
        try:
            result = subprocess.run(
                ["git", "push", "-u", "origin", branch_name],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                env=self.env
            )
            
            if result.returncode == 0:
                return {"success": True, "message": "브랜치가 성공적으로 푸시되었습니다"}
            else:
                return {
                    "success": False,
                    "error": f"브랜치 푸시 실패: {result.stderr}",
                    "stderr": result.stderr
                }
                
        except Exception as e:
            logger.error(f"브랜치 푸시 실패: {e}")
            return {"success": False, "error": str(e)}
    
    def _should_create_pr(self, patch: PatchProposal) -> bool:
        """자동 PR 생성을 위한 조건 확인"""
        # 1. 신뢰도 점수 확인
        if patch.confidence < 0.7:
            return False
        
        # 2. 심각도 기반 자동 PR 생성 (고위험만)
        # 이 부분은 SecurityFinding의 severity 정보가 필요하므로
        # 실제 구현에서는 finding 정보를 전달받아야 함
        return True
    
    def _create_pull_request(self, patch: PatchProposal, branch_name: str) -> Dict[str, Any]:
        """GitHub PR 생성"""
        try:
            # GitHub CLI를 사용한 PR 생성
            pr_title = f"🔒 {patch.commit_message}"
            pr_body = self._generate_pr_body(patch)
            
            # gh pr create 명령어 실행
            result = subprocess.run([
                "gh", "pr", "create",
                "--title", pr_title,
                "--body", pr_body,
                "--head", branch_name,
                "--base", "main"  # 기본 브랜치명은 설정 가능
            ], cwd=self.repo_path, capture_output=True, text=True, env=self.env)
            
            if result.returncode == 0:
                # PR URL 추출
                output_lines = result.stdout.strip().split('\n')
                pr_url = None
                pr_number = None
                
                for line in output_lines:
                    if line.startswith('https://github.com/'):
                        pr_url = line.strip()
                        # PR 번호 추출
                        if '/pull/' in pr_url:
                            pr_number = pr_url.split('/pull/')[-1]
                        break
                
                return {
                    "success": True,
                    "message": "PR이 성공적으로 생성되었습니다",
                    "pr_url": pr_url,
                    "pr_number": pr_number
                }
            else:
                return {
                    "success": False,
                    "error": f"PR 생성 실패: {result.stderr}",
                    "stderr": result.stderr
                }
                
        except Exception as e:
            logger.error(f"PR 생성 실패: {e}")
            return {"success": False, "error": str(e)}
    
    def _generate_pr_body(self, patch: PatchProposal) -> str:
        """PR 본문 생성"""
        body = f"""## 🔒 보안 취약점 자동 수정

### 📋 수정 내용
{patch.explanation}

### 🛠️ 적용된 패치
```diff
{patch.diff}
```

### 🧪 테스트 코드
```python
{patch.test_snippet}
```

### 📊 위험도 평가
- **패치 전**: {patch.finding_id}
- **패치 후**: {patch.risk_assessment}
- **신뢰도**: {patch.confidence:.1%}

### 🔄 대안적 접근 방법
"""
        
        if patch.alternative_approaches:
            for approach in patch.alternative_approaches:
                body += f"- {approach}\n"
        else:
            body += "- 제안된 패치가 최적의 해결책입니다\n"
        
        body += f"""
### 📝 커밋 정보
- **메시지**: {patch.commit_message}
- **상세**: {patch.commit_body}

---
*이 PR은 FortiCode의 자동 보안 분석 시스템에 의해 생성되었습니다.*
"""
        
        return body
    
    def batch_apply_patches(self, 
                           patches: List[PatchProposal],
                           code_snippets: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """여러 패치를 배치로 적용"""
        results = []
        
        for patch in patches:
            code_snippet = code_snippets.get(patch.finding_id) if code_snippets else None
            result = self.apply_patch(patch, code_snippet)
            results.append({
                "finding_id": patch.finding_id,
                "result": result
            })
        
        return results
    
    def validate_patch_application(self, patch: PatchProposal) -> Dict[str, Any]:
        """패치 적용 전 유효성 검증"""
        validation_result = {
            "is_valid": True,
            "issues": [],
            "warnings": [],
            "recommendations": []
        }
        
        # 1. diff 형식 검증
        if not patch.diff:
            validation_result["is_valid"] = False
            validation_result["issues"].append("패치 내용이 없습니다")
        
        # 2. 신뢰도 점수 검증
        if patch.confidence < 0.5:
            validation_result["warnings"].append("낮은 신뢰도 - 수동 검토 권장")
            validation_result["recommendations"].append("패치 적용 전 코드 리뷰 수행")
        
        # 3. 테스트 코드 검증
        if not patch.test_snippet:
            validation_result["warnings"].append("테스트 코드가 없습니다")
            validation_result["recommendations"].append("테스트 코드 작성 후 적용")
        
        # 4. 커밋 메시지 검증
        if not patch.commit_message:
            validation_result["is_valid"] = False
            validation_result["issues"].append("커밋 메시지가 없습니다")
        
        return validation_result

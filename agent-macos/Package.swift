// swift-tools-version:5.9
import PackageDescription

// OwlWatch macOS 에이전트.
//
// 규칙 엔진과 정규화 JSON 은 순수 Swift 라 SwiftPM 으로 빌드·테스트된다.
// 수집기는 Endpoint Security 프레임워크를 쓰므로 시스템 확장 타깃에서만 링크된다 —
// Xcode 프로젝트가 필요하고 Apple 엔타이틀먼트 승인이 선결이다(설계서 M0·M4).
//
// 승인 없이도 오늘 할 수 있는 것: swift run owlwatch-specrunner
// spec/fixtures 를 돌려 Windows 포트·JS 레퍼런스와 같은 체인 해시가 나오는지 확인한다.

let package = Package(
    name: "OwlWatch",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "OwlWatchCore", targets: ["OwlWatchCore"]),
        .library(name: "OwlWatchRules", targets: ["OwlWatchRules"]),
        .executable(name: "owlwatch-specrunner", targets: ["owlwatch-specrunner"]),
    ],
    targets: [
        .target(name: "OwlWatchCore"),
        .target(name: "OwlWatchRules", dependencies: ["OwlWatchCore"]),

        // Endpoint Security 를 링크한다. 엔타이틀먼트가 없으면 실행 시 클라이언트 생성이 실패한다.
        .target(
            name: "OwlWatchCollectors",
            dependencies: ["OwlWatchCore"],
            linkerSettings: [.linkedLibrary("EndpointSecurity")]
        ),

        .executableTarget(name: "owlwatch-specrunner", dependencies: ["OwlWatchRules"]),
    ]
)

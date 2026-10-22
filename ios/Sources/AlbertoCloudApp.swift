import SwiftUI
import WebKit
import UIKit
import Security

@main
struct AlbertoCloudApp: App {
    var body: some Scene {
        WindowGroup {
            LiquidGlassStudioView()
                .preferredColorScheme(.dark)
        }
    }
}

// MARK: - Domain Models

struct CloudWindow: Decodable, Identifiable, Equatable {
    let id: String
    let title: String
}

struct CloudCLIStatus: Decodable, Identifiable, Equatable {
    var id: String { name }
    let name: String
    let icon: String
    let authed: Bool
}

struct MachineProcess: Decodable, Identifiable, Equatable {
    var id: String { "\(pid)-\(name)" }
    let pid: String
    let cpu: Double
    let mem: Double
    let name: String
}

struct FleetMachine: Decodable, Identifiable, Equatable {
    let id: String
    let name: String
    let kind: String
    let chip: String
    let os: String
    let ip: String
    let online: Bool
    let has_gui_stream: Bool
    let cpu_pct: Double
    let load_1m: Double
    let mem_used_gb: Double
    let mem_total_gb: Double
    let disk_used_gb: Double
    let disk_total_gb: Double
    let uptime: String
    let battery_pct: Int?
    let windows: [CloudWindow]?
    let clis: [CloudCLIStatus]?
    let top_processes: [MachineProcess]
    let terminal_log: String
}

struct CloudVMItem: Decodable, Identifiable, Equatable {
    let id: String
    let label: String
    let state: String
    let provider: String
    let image: String
}

struct FleetResponse: Decodable {
    let updated_at: Int?
    let machines: [FleetMachine]
    let cloud_vms: [CloudVMItem]
}

struct ExecResponse: Decodable {
    let ok: Bool?
    let exit_code: Int?
    let elapsed_ms: Int?
    let message: String?
    let output: String?
}

struct ActionResponse: Decodable {
    let ok: Bool?
    let message: String?
}

struct ProviderItem: Identifiable {
    let id: String
    let assetName: String
    let title: String
    let vendor: String
    let flag: String
    let glow: Color
}

enum MonitorClickMode: String, CaseIterable, Identifiable {
    case single = "Click"
    case double = "2× Click"
    case right = "Right"

    var id: String { rawValue }
    var actionName: String {
        switch self {
        case .single: return "desktop:click"
        case .double: return "desktop:doubleclick"
        case .right: return "desktop:rightclick"
        }
    }
}

enum CockpitTab: String, CaseIterable, Identifiable {
    case studio = "Studio"
    case terminal = "Terminal"
    case processes = "Processes"
    case cloudVMs = "Cloud VMs"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .studio: return "sparkles.rectangle.stack.fill"
        case .terminal: return "terminal.fill"
        case .processes: return "cpu.fill"
        case .cloudVMs: return "server.rack"
        }
    }
}

// MARK: - Strict TLS Evaluation

enum TLSTrustEvaluator {
    static func isLoopbackHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        return lower == "127.0.0.1" || lower == "localhost" || lower == "::1" || lower == "[::1]"
    }

    static func evaluate(
        challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let host = challenge.protectionSpace.host
        if host.isEmpty {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        var cfError: CFError?
        if SecTrustEvaluateWithError(trust, &cfError) {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        #if DEBUG
        if isLoopbackHost(host) {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        #endif
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

enum KeychainTokenStore {
    private static let service = "ai.burnbar.alberto-cloud.mission-control"
    private static let account = "bearer-token"
    static let primaryOrigin = "https://albertos-mac-studio.tailbf4ff5.ts.net:8443"

    static func originKey(for url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(),
              (scheme == "https" || scheme == "http"),
              let host = url.host?.lowercased(),
              !host.isEmpty else {
            return nil
        }
        let defaultPort = (scheme == "https") ? 443 : 80
        let port = url.port ?? defaultPort
        return port == defaultPort ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port)"
    }

    static func configuredPrimaryOriginKey() -> String {
        if let raw = ProcessInfo.processInfo.environment["MISSION_CONTROL_ORIGIN"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           let url = URL(string: raw),
           let key = originKey(for: url) {
            return key
        }
        return primaryOrigin
    }

    static func isPinnedPrimaryOrigin(_ url: URL) -> Bool {
        guard let key = originKey(for: url) else { return false }
        return key == configuredPrimaryOriginKey()
    }

    private static func loadAccount(_ accountName: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountName,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !str.isEmpty else {
            return nil
        }
        return str
    }

    static func loadToken(for url: URL? = nil) -> String? {
        if let url, let key = originKey(for: url) {
            if let scoped = loadAccount("\(account):\(key)") {
                return scoped
            }
            guard isPinnedPrimaryOrigin(url) else {
                return nil
            }
        }
        return loadAccount(account)
    }

    @discardableResult
    static func saveToken(_ token: String, for url: URL) -> Bool {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let key = originKey(for: url), let data = trimmed.data(using: .utf8) else {
            return false
        }
        let accountName = "\(account):\(key)"
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountName
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: accountName,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
    }
}

final class StrictTLSDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        TLSTrustEvaluator.evaluate(challenge: challenge, completionHandler: completionHandler)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

enum FittedImageGeometry {
    static func normalizedPoint(location: CGPoint, in containerSize: CGSize, imageSize: CGSize) -> CGPoint? {
        guard containerSize.width > 0, containerSize.height > 0,
              imageSize.width > 0, imageSize.height > 0 else {
            return nil
        }
        let scale = min(containerSize.width / imageSize.width, containerSize.height / imageSize.height)
        let fittedWidth = imageSize.width * scale
        let fittedHeight = imageSize.height * scale
        let originX = (containerSize.width - fittedWidth) * 0.5
        let originY = (containerSize.height - fittedHeight) * 0.5
        let relX = (location.x - originX) / max(1.0, fittedWidth)
        let relY = (location.y - originY) / max(1.0, fittedHeight)
        guard relX >= 0.0, relX <= 1.0, relY >= 0.0, relY <= 1.0 else {
            return nil
        }
        return CGPoint(x: min(1.0, max(0.0, relX)), y: min(1.0, max(0.0, relY)))
    }
}

// MARK: - ViewModel

@MainActor
final class CloudStudioViewModel: ObservableObject {
    @Published var machines: [FleetMachine] = [
        FleetMachine(
            id: "alberto-dev",
            name: "alberto-dev",
            kind: "cloud-desktop",
            chip: "8 vCPU • Cloud X11",
            os: "Ubuntu 24.04 • DISPLAY :1",
            ip: "100.94.33.26:7778",
            online: true,
            has_gui_stream: true,
            cpu_pct: 4.2,
            load_1m: 0.3,
            mem_used_gb: 2.9,
            mem_total_gb: 15.6,
            disk_used_gb: 24.1,
            disk_total_gb: 62.8,
            uptime: "Live",
            battery_pct: nil,
            windows: [],
            clis: [],
            top_processes: [],
            terminal_log: "$ uname -a\nLinux alberto-dev • 44 AI & Dev CLIs Ready"
        ),
        FleetMachine(
            id: "mac-studio",
            name: "Mac Studio",
            kind: "mac",
            chip: "Apple M5 Max • 18C",
            os: "macOS Tahoe 27",
            ip: "192.168.1.126 • 100.94.33.26",
            online: true,
            has_gui_stream: false,
            cpu_pct: 12.0,
            load_1m: 2.1,
            mem_used_gb: 18.4,
            mem_total_gb: 64.0,
            disk_used_gb: 240.0,
            disk_total_gb: 1000.0,
            uptime: "Live",
            battery_pct: nil,
            windows: [],
            clis: [],
            top_processes: [],
            terminal_log: "$ sysctl -n machdep.cpu.brand_string\nApple M5 Max (64 GB)"
        ),
        FleetMachine(
            id: "macbook-pro",
            name: "MacBook Pro",
            kind: "mac",
            chip: "Apple M5 Max • 18C",
            os: "macOS Tahoe 27",
            ip: "192.168.1.163 • 100.83.10.11",
            online: true,
            has_gui_stream: false,
            cpu_pct: 8.5,
            load_1m: 1.5,
            mem_used_gb: 14.2,
            mem_total_gb: 48.0,
            disk_used_gb: 180.0,
            disk_total_gb: 1000.0,
            uptime: "Live",
            battery_pct: 95,
            windows: [],
            clis: [],
            top_processes: [],
            terminal_log: "$ ssh mbp-hub hostname\nAlbertos-MacBook-Pro.local"
        ),
        FleetMachine(
            id: "mac-mini",
            name: "Mac Mini M4",
            kind: "mac",
            chip: "Apple M4 Pro • 12C",
            os: "macOS Tahoe 27",
            ip: "100.101.209.102",
            online: true,
            has_gui_stream: false,
            cpu_pct: 6.4,
            load_1m: 0.9,
            mem_used_gb: 6.8,
            mem_total_gb: 24.0,
            disk_used_gb: 110.0,
            disk_total_gb: 500.0,
            uptime: "Live",
            battery_pct: nil,
            windows: [],
            clis: [],
            top_processes: [],
            terminal_log: "$ ssh mac-mini hostname\nTikkas-Mac-mini.local"
        )
    ]
    @Published var cloudVMs: [CloudVMItem] = []
    @Published var selectedMachineID: String = "alberto-dev"
    @Published var activeTab: CockpitTab = .studio
    @Published var isLaunchpadExpanded: Bool = false
    @Published var screenImage: UIImage?
    @Published var routeName: String = "Tailscale TLS"
    @Published var latencyMs: Int = 9
    @Published var isConnected: Bool = false
    @Published var isRunningCommand: Bool = false
    @Published var toastMessage: String?
    @Published var useInteractiveWebVNC: Bool = false
    @Published var clickMode: MonitorClickMode = .single
    @Published var activeEndpoint: String = KeychainTokenStore.primaryOrigin

    let endpoints: [(name: String, url: String)] = [
        ("Tailscale TLS", KeychainTokenStore.primaryOrigin),
        ("Cloud Edge", "https://lofty-indigo-meerkat--alberto-s-team--7777.cmux.sh"),
        ("Tailscale IP TLS", "https://100.94.33.26:8443")
    ]

    var currentMachine: FleetMachine {
        machines.first(where: { $0.id == selectedMachineID }) ?? machines[0]
    }

    private let session: URLSession
    private var fleetPollTask: Task<Void, Never>?
    private var screenshotPollTask: Task<Void, Never>?
    private var routeProbeInFlight = false
    private var screenshotFetchInFlight = false
    private var inFlightCommandCount = 0

    init() {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 4.5
        cfg.timeoutIntervalForResource = 12.0
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        self.session = URLSession(configuration: cfg, delegate: StrictTLSDelegate(), delegateQueue: nil)
    }

    func resolveAuthToken(for url: URL) -> String? {
        if let keychainToken = KeychainTokenStore.loadToken(for: url) {
            return keychainToken
        }
        guard KeychainTokenStore.isPinnedPrimaryOrigin(url) else {
            return nil
        }
        if let envToken = ProcessInfo.processInfo.environment["MISSION_CONTROL_TOKEN"]?.trimmingCharacters(in: .whitespacesAndNewlines),
           !envToken.isEmpty {
            return envToken
        }
        return nil
    }

    private func authorizedRequest(url: URL, method: String = "GET", jsonBody: [String: Any]? = nil) -> URLRequest {
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let token = resolveAuthToken(for: url) {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let jsonBody {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: jsonBody)
        }
        return req
    }

    func start() {
        guard fleetPollTask == nil else { return }

        fleetPollTask = Task { [weak self] in
            guard let self else { return }
            await self.selectFastestRoute()
            while !Task.isCancelled {
                await self.refreshFleet()
                try? await Task.sleep(nanoseconds: 2_600_000_000)
            }
        }

        screenshotPollTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                if self.selectedMachineID == "alberto-dev" && !self.useInteractiveWebVNC && self.activeTab == .studio {
                    await self.refreshScreenshot()
                }
                try? await Task.sleep(nanoseconds: 600_000_000)
            }
        }
    }

    func stop() {
        fleetPollTask?.cancel()
        fleetPollTask = nil
        screenshotPollTask?.cancel()
        screenshotPollTask = nil
    }

    func selectFastestRoute() async {
        guard !routeProbeInFlight else { return }
        routeProbeInFlight = true
        defer { routeProbeInFlight = false }

        for ep in endpoints {
            guard let url = URL(string: "\(ep.url)/api/fleet"),
                  resolveAuthToken(for: url) != nil else { continue }
            let t0 = DispatchTime.now()
            do {
                let req = authorizedRequest(url: url)
                let (data, resp) = try await session.data(for: req)
                if let http = resp as? HTTPURLResponse, http.statusCode == 200,
                   let decoded = try? JSONDecoder().decode(FleetResponse.self, from: data),
                   !decoded.machines.isEmpty {
                    let elapsedMs = Int((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
                    self.activeEndpoint = ep.url
                    self.routeName = ep.name
                    self.latencyMs = max(1, elapsedMs)
                    self.machines = decoded.machines
                    self.cloudVMs = decoded.cloud_vms
                    self.isConnected = true
                    await refreshScreenshot()
                    return
                }
            } catch {
                continue
            }
        }
        self.isConnected = false
    }

    func refreshFleet() async {
        guard let url = URL(string: "\(activeEndpoint)/api/fleet") else { return }
        let t0 = DispatchTime.now()
        do {
            let req = authorizedRequest(url: url)
            let (data, resp) = try await session.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode == 200 {
                let decoded = try JSONDecoder().decode(FleetResponse.self, from: data)
                if !decoded.machines.isEmpty {
                    let elapsedMs = Int((DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000)
                    self.latencyMs = max(1, elapsedMs)
                    self.machines = decoded.machines
                    self.cloudVMs = decoded.cloud_vms
                    self.isConnected = true
                }
                return
            }
            self.isConnected = false
            await selectFastestRoute()
        } catch {
            self.isConnected = false
            await selectFastestRoute()
        }
    }

    func refreshScreenshot() async {
        guard !screenshotFetchInFlight else { return }
        screenshotFetchInFlight = true
        defer { screenshotFetchInFlight = false }
        let ts = Int(Date().timeIntervalSince1970 * 1000)
        guard let url = URL(string: "\(activeEndpoint)/api/screenshot?t=\(ts)") else { return }
        do {
            let req = authorizedRequest(url: url)
            let (data, resp) = try await session.data(for: req)
            if let http = resp as? HTTPURLResponse, http.statusCode == 200,
               data.count <= 12 * 1024 * 1024,
               let img = UIImage(data: data) {
                self.screenImage = img
                self.isConnected = true
            }
        } catch {}
    }

    func runCommandOnSelectedMachine(_ cmd: String, targetOverride: String? = nil, action: String = "") {
        let target = targetOverride ?? selectedMachineID
        UIImpactFeedbackGenerator(style: .rigid).impactOccurred()
        inFlightCommandCount += 1
        isRunningCommand = true
        Task {
            defer {
                inFlightCommandCount = max(0, inFlightCommandCount - 1)
                isRunningCommand = inFlightCommandCount > 0
            }
            guard let url = URL(string: "\(activeEndpoint)/api/fleet/exec") else { return }
            let req = authorizedRequest(
                url: url,
                method: "POST",
                jsonBody: [
                    "machine": target,
                    "cmd": cmd,
                    "action": action
                ]
            )
            do {
                let (data, resp) = try await session.data(for: req)
                guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                    presentToast("Command rejected by host")
                    return
                }
                if let res = try? JSONDecoder().decode(ExecResponse.self, from: data) {
                    presentToast(res.message ?? "Executed on \(target)")
                } else {
                    presentToast("Executed on \(target)")
                }
                await refreshFleet()
                if target == "alberto-dev" {
                    try? await Task.sleep(nanoseconds: 250_000_000)
                    await refreshScreenshot()
                }
            } catch {
                presentToast("Reconnecting...")
                await selectFastestRoute()
            }
        }
    }

    func triggerX11Action(_ action: String, arg: String = "") {
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        Task {
            guard let url = URL(string: "\(activeEndpoint)/api/action") else { return }
            let req = authorizedRequest(
                url: url,
                method: "POST",
                jsonBody: ["action": action, "arg": arg]
            )
            do {
                let (data, resp) = try await session.data(for: req)
                guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                    presentToast("Action rejected by host")
                    return
                }
                if let res = try? JSONDecoder().decode(ActionResponse.self, from: data),
                   let msg = res.message {
                    presentToast(msg)
                }
                try? await Task.sleep(nanoseconds: 240_000_000)
                await refreshScreenshot()
                await refreshFleet()
            } catch {}
        }
    }

    func presentToast(_ text: String) {
        withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
            toastMessage = text
        }
        Task {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if toastMessage == text {
                withAnimation(.easeOut(duration: 0.2)) {
                    toastMessage = nil
                }
            }
        }
    }
}

// MARK: - Liquid Glass Design System Primitives

struct AmbientAuroraBackground: View {
    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 20.0)) { timeline in
            let t = timeline.date.timeIntervalSinceReferenceDate
            ZStack {
                Color(red: 0.02, green: 0.03, blue: 0.06)

                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color(red: 0.36, green: 0.40, blue: 0.98).opacity(0.28), .clear],
                            center: .center,
                            startRadius: 10,
                            endRadius: 260
                        )
                    )
                    .frame(width: 480, height: 480)
                    .offset(x: CGFloat(cos(t * 0.25) * 90 - 70), y: CGFloat(sin(t * 0.2) * 80 - 240))

                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color(red: 0.14, green: 0.74, blue: 0.96).opacity(0.22), .clear],
                            center: .center,
                            startRadius: 10,
                            endRadius: 240
                        )
                    )
                    .frame(width: 440, height: 440)
                    .offset(x: CGFloat(sin(t * 0.22) * 100 + 90), y: CGFloat(cos(t * 0.18) * 90 - 40))

                Circle()
                    .fill(
                        RadialGradient(
                            colors: [Color(red: 0.62, green: 0.28, blue: 0.96).opacity(0.18), .clear],
                            center: .center,
                            startRadius: 10,
                            endRadius: 270
                        )
                    )
                    .frame(width: 500, height: 500)
                    .offset(x: CGFloat(cos(t * 0.17) * 70), y: CGFloat(sin(t * 0.24) * 70 + 260))
            }
            .ignoresSafeArea()
        }
    }
}

struct LiquidSpecularBorder: View {
    var cornerRadius: CGFloat = 22
    var tint: Color = .white

    var body: some View {
        RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            .strokeBorder(
                LinearGradient(
                    stops: [
                        .init(color: .white.opacity(0.42), location: 0.0),
                        .init(color: tint.opacity(0.24), location: 0.25),
                        .init(color: .white.opacity(0.05), location: 0.58),
                        .init(color: tint.opacity(0.20), location: 1.0)
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                lineWidth: 1.1
            )
    }
}

struct LiquidGlassSurface<Content: View>: View {
    var cornerRadius: CGFloat = 22
    var tint: Color = .white
    @ViewBuilder let content: Content

    var body: some View {
        content
            .background(
                ZStack {
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(.ultraThinMaterial)
                    RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [
                                    tint.opacity(0.09),
                                    Color.white.opacity(0.02)
                                ],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                }
            )
            .overlay(LiquidSpecularBorder(cornerRadius: cornerRadius, tint: tint))
            .shadow(color: .black.opacity(0.36), radius: 16, x: 0, y: 8)
    }
}

struct LiquidSpringButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.955 : 1.0)
            .brightness(configuration.isPressed ? 0.06 : 0.0)
            .animation(.spring(response: 0.24, dampingFraction: 0.72), value: configuration.isPressed)
    }
}

// MARK: - Main Studio View

struct LiquidGlassStudioView: View {
    @StateObject private var vm = CloudStudioViewModel()
    @State private var customCommand = ""
    @State private var showFullscreenMonitor = false
    @State private var tapRipplePoint: CGPoint?
    @State private var tapRippleScale: CGFloat = 0.3
    @State private var tapRippleOpacity: Double = 0.0

    private let providers: [ProviderItem] = [
        .init(id: "agent:claude", assetName: "provider-claude", title: "Claude Code", vendor: "Anthropic", flag: "--skip-permissions", glow: Color(red: 0.92, green: 0.48, blue: 0.28)),
        .init(id: "agent:codex", assetName: "provider-codex", title: "OpenAI Codex", vendor: "ChatGPT Pro", flag: "codex --yolo", glow: Color(red: 0.22, green: 0.84, blue: 0.62)),
        .init(id: "agent:agy", assetName: "provider-agy", title: "Antigravity", vendor: "Google DeepMind", flag: "agy 1.3.5", glow: Color(red: 0.38, green: 0.56, blue: 0.98)),
        .init(id: "agent:muse", assetName: "provider-muse", title: "Meta Muse", vendor: "Meta AI", flag: "muse --yolo", glow: Color(red: 0.25, green: 0.62, blue: 1.0)),
        .init(id: "agent:devin", assetName: "provider-devin", title: "Devin CLI", vendor: "Cognition", flag: "Autonomous 3000.11", glow: Color(red: 0.20, green: 0.85, blue: 0.92)),
        .init(id: "agent:grok", assetName: "provider-grok", title: "xAI Grok", vendor: "xAI", flag: "grok 1.0.52", glow: Color(red: 0.90, green: 0.92, blue: 0.98)),
        .init(id: "agent:gemini", assetName: "provider-gemini", title: "Gemini CLI", vendor: "Google", flag: "Gemini 2.5 Pro", glow: Color(red: 0.35, green: 0.60, blue: 0.98)),
        .init(id: "agent:junie", assetName: "provider-junie", title: "JetBrains Junie", vendor: "JetBrains", flag: "junie 26.10.12", glow: Color(red: 0.32, green: 0.86, blue: 0.48)),
        .init(id: "agent:kimi", assetName: "provider-kimi", title: "Kimi CLI", vendor: "Moonshot AI", flag: "kimi 1.52.0", glow: Color(red: 0.48, green: 0.58, blue: 0.98)),
        .init(id: "agent:opencode", assetName: "provider-opencode", title: "OpenCode", vendor: "OpenCode TUI", flag: "Multi-Model", glow: Color(red: 0.72, green: 0.48, blue: 0.98))
    ]

    private let quickKeys: [(label: String, key: String)] = [
        ("⏎ Enter", "Return"),
        ("⎋ Esc", "Escape"),
        ("⇥ Tab", "Tab"),
        ("^C Stop", "ctrl+c"),
        ("^L Clear", "ctrl+l"),
        ("↑ Prev", "Up"),
        ("↓ Next", "Down"),
        ("⌥ Tab", "alt+Tab")
    ]

    private let quickDiagnosticCommands: [(label: String, cmd: String)] = [
        ("System Info", "uname -a && uptime"),
        ("Top CPU", "ps aux | head -n 12"),
        ("Disk Space", "df -h /"),
        ("Git Status", "git status -sb 2>/dev/null || ls -la"),
        ("Network / Tailscale", "tailscale status 2>/dev/null || ip addr"),
        ("Verify CLIs", "claude --version && codex --version && gh --version")
    ]

    var body: some View {
        ZStack(alignment: .bottom) {
            AmbientAuroraBackground()

            VStack(spacing: 8) {
                topFleetHeaderBar
                    .padding(.horizontal, 12)
                    .padding(.top, 4)

                machineSwitcherRibbon

                cockpitModePicker
                    .padding(.horizontal, 12)

                ScrollView(.vertical, showsIndicators: false) {
                    VStack(spacing: 12) {
                        telemetryGlassStrip

                        switch vm.activeTab {
                        case .studio:
                            if vm.currentMachine.has_gui_stream {
                                liveDisplayStudioCard
                            } else {
                                macHardwareOverviewCard
                            }
                            collapsibleProviderLaunchpad
                            liveTerminalConsoleCard(compact: true)

                        case .terminal:
                            liveTerminalConsoleCard(compact: false)
                            collapsibleProviderLaunchpad

                        case .processes:
                            processesAndWindowsCard

                        case .cloudVMs:
                            cloudVMsFleetCard
                        }
                    }
                    .padding(.horizontal, 12)
                    .padding(.top, 2)
                    .padding(.bottom, 130)
                }
            }

            floatingCommandDock
                .padding(.horizontal, 10)
                .padding(.bottom, 6)

            if let toast = vm.toastMessage {
                HStack(spacing: 8) {
                    Image(systemName: "bolt.horizontal.circle.fill")
                        .foregroundColor(.cyan)
                    Text(toast)
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
                .background(.ultraThinMaterial, in: Capsule())
                .overlay(Capsule().strokeBorder(Color.white.opacity(0.32), lineWidth: 1))
                .shadow(color: .black.opacity(0.45), radius: 14, y: 6)
                .padding(.bottom, 114)
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .onAppear {
            vm.start()
        }
        .onDisappear {
            vm.stop()
        }
        .fullScreenCover(isPresented: $showFullscreenMonitor) {
            FullscreenGlassDisplaySheet(vm: vm)
        }
    }

    // MARK: - Top Fleet Header Bar

    private var topFleetHeaderBar: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 11, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [Color.indigo.opacity(0.48), Color.cyan.opacity(0.28)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 34, height: 34)
                    .overlay(LiquidSpecularBorder(cornerRadius: 11, tint: .cyan))

                Image("provider-agy")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 20, height: 20)
            }

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text("Alberto Fleet & Cloud")
                        .font(.system(size: 15.5, weight: .heavy, design: .rounded))
                        .foregroundColor(.white)
                    HStack(spacing: 4) {
                        Circle()
                            .fill(vm.isConnected ? Color.green : Color.orange)
                            .frame(width: 6, height: 6)
                        Text("\(vm.latencyMs)ms")
                            .font(.system(size: 10, weight: .bold, design: .monospaced))
                            .foregroundColor(vm.isConnected ? .green : .orange)
                    }
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.green.opacity(0.14), in: Capsule())
                }
                Text("\(vm.machines.count) Machines + \(vm.cloudVMs.count) Cloud VMs • \(vm.routeName)")
                    .font(.system(size: 10.5, weight: .medium, design: .rounded))
                    .foregroundColor(.white.opacity(0.62))
            }

            Spacer()

            Menu {
                ForEach(vm.endpoints, id: \.url) { ep in
                    Button {
                        UISelectionFeedbackGenerator().selectionChanged()
                        vm.activeEndpoint = ep.url
                        vm.routeName = ep.name
                        Task { await vm.refreshFleet() }
                    } label: {
                        Label(ep.name, systemImage: vm.activeEndpoint == ep.url ? "checkmark.circle.fill" : "network")
                    }
                }
            } label: {
                Image(systemName: "antenna.radiowaves.left.and.right")
                    .font(.system(size: 12.5, weight: .bold))
                    .foregroundColor(.cyan)
                    .frame(width: 32, height: 32)
                    .background(.ultraThinMaterial, in: Circle())
                    .overlay(Circle().strokeBorder(Color.white.opacity(0.24), lineWidth: 0.8))
            }

            Button {
                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                Task { await vm.refreshFleet() }
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 12.5, weight: .bold))
                    .foregroundColor(.white)
                    .frame(width: 32, height: 32)
                    .background(.ultraThinMaterial, in: Circle())
                    .overlay(Circle().strokeBorder(Color.white.opacity(0.24), lineWidth: 0.8))
            }
        }
    }

    // MARK: - Multi-Machine Switcher Ribbon

    private var machineSwitcherRibbon: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(vm.machines) { machine in
                    let isSelected = machine.id == vm.selectedMachineID
                    Button {
                        UISelectionFeedbackGenerator().selectionChanged()
                        withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                            vm.selectedMachineID = machine.id
                        }
                    } label: {
                        HStack(spacing: 9) {
                            Image(systemName: iconForMachine(machine))
                                .font(.system(size: 15, weight: .semibold))
                                .foregroundColor(isSelected ? .cyan : .white.opacity(0.75))
                                .frame(width: 30, height: 30)
                                .background(
                                    (isSelected ? Color.cyan.opacity(0.22) : Color.white.opacity(0.07)),
                                    in: RoundedRectangle(cornerRadius: 9, style: .continuous)
                                )

                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 5) {
                                    Text(machine.name)
                                        .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                        .foregroundColor(.white)
                                    Circle()
                                        .fill(machine.online ? Color.green : Color.red)
                                        .frame(width: 5.5, height: 5.5)
                                }
                                Text("\(Int(machine.cpu_pct))% CPU • \(String(format: "%.0f", machine.mem_used_gb))/\(String(format: "%.0fG", machine.mem_total_gb))")
                                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                                    .foregroundColor(isSelected ? .cyan : .white.opacity(0.55))
                            }
                        }
                        .padding(.horizontal, 11)
                        .padding(.vertical, 8)
                        .background(
                            ZStack {
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .fill(.ultraThinMaterial)
                                if isSelected {
                                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                                        .fill(Color.cyan.opacity(0.14))
                                }
                            }
                        )
                        .overlay(
                            LiquidSpecularBorder(
                                cornerRadius: 16,
                                tint: isSelected ? .cyan : .white.opacity(0.3)
                            )
                        )
                    }
                    .buttonStyle(LiquidSpringButtonStyle())
                }
            }
            .padding(.horizontal, 12)
        }
    }

    private func iconForMachine(_ machine: FleetMachine) -> String {
        switch machine.id {
        case "alberto-dev": return "cloud.bolt.fill"
        case "mac-studio": return "macstudio.fill"
        case "macbook-pro": return "laptopcomputer"
        case "mac-mini": return "macmini.fill"
        default: return "server.rack"
        }
    }

    // MARK: - Cockpit Mode Segmented Picker

    private var cockpitModePicker: some View {
        HStack(spacing: 6) {
            ForEach(CockpitTab.allCases) { tab in
                let active = vm.activeTab == tab
                Button {
                    UISelectionFeedbackGenerator().selectionChanged()
                    withAnimation(.spring(response: 0.26, dampingFraction: 0.8)) {
                        vm.activeTab = tab
                    }
                } label: {
                    HStack(spacing: 5) {
                        Image(systemName: tab.icon)
                            .font(.system(size: 11, weight: .semibold))
                        Text(tab.rawValue)
                            .font(.system(size: 11.5, weight: .bold, design: .rounded))
                    }
                    .foregroundColor(active ? .white : .white.opacity(0.62))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(
                        active
                            ? AnyShapeStyle(LinearGradient(colors: [Color.indigo.opacity(0.65), Color.cyan.opacity(0.45)], startPoint: .topLeading, endPoint: .bottomTrailing))
                            : AnyShapeStyle(Color.white.opacity(0.05)),
                        in: Capsule()
                    )
                    .overlay(
                        Capsule()
                            .strokeBorder(active ? Color.cyan.opacity(0.55) : Color.white.opacity(0.10), lineWidth: 0.9)
                    )
                }
                .buttonStyle(LiquidSpringButtonStyle())
            }
        }
    }

    // MARK: - Telemetry Strip for Active Machine

    private var telemetryGlassStrip: some View {
        let m = vm.currentMachine
        return HStack(spacing: 8) {
            telemetryGauge(
                title: "CPU",
                value: String(format: "%.0f%%", m.cpu_pct),
                fraction: min(1.0, m.cpu_pct / 100.0),
                tint: .cyan
            )
            telemetryGauge(
                title: "RAM",
                value: String(format: "%.1f/%.0fG", m.mem_used_gb, m.mem_total_gb),
                fraction: min(1.0, m.mem_used_gb / max(1.0, m.mem_total_gb)),
                tint: .indigo
            )
            telemetryGauge(
                title: "DISK",
                value: String(format: "%.0f/%.0fG", m.disk_used_gb, m.disk_total_gb),
                fraction: min(1.0, m.disk_used_gb / max(1.0, m.disk_total_gb)),
                tint: .purple
            )
            telemetryGauge(
                title: m.battery_pct != nil ? "BATTERY" : "UPTIME",
                value: m.battery_pct != nil ? "\(m.battery_pct!)%" : m.uptime,
                fraction: m.battery_pct != nil ? Double(m.battery_pct!) / 100.0 : 1.0,
                tint: .mint
            )
        }
    }

    private func telemetryGauge(title: String, value: String, fraction: Double, tint: Color) -> some View {
        LiquidGlassSurface(cornerRadius: 15, tint: tint) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 9, weight: .heavy, design: .rounded))
                    .foregroundColor(.white.opacity(0.52))
                Text(value)
                    .font(.system(size: 12, weight: .bold, design: .rounded))
                    .foregroundColor(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule().fill(Color.white.opacity(0.10))
                        Capsule()
                            .fill(LinearGradient(colors: [tint, tint.opacity(0.55)], startPoint: .leading, endPoint: .trailing))
                            .frame(width: max(6, geo.size.width * fraction))
                    }
                }
                .frame(height: 3.5)
            }
            .padding(.horizontal, 9)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Collapsible LobeHub AI Provider Launchpad

    private var collapsibleProviderLaunchpad: some View {
        LiquidGlassSurface(cornerRadius: 22, tint: .cyan) {
            VStack(alignment: .leading, spacing: 0) {
                Button {
                    UISelectionFeedbackGenerator().selectionChanged()
                    withAnimation(.spring(response: 0.3, dampingFraction: 0.78)) {
                        vm.isLaunchpadExpanded.toggle()
                    }
                } label: {
                    HStack(spacing: 10) {
                        HStack(spacing: -6) {
                            ForEach(providers.prefix(5)) { p in
                                Image(p.assetName)
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 18, height: 18)
                                    .padding(4)
                                    .background(Color(red: 0.08, green: 0.10, blue: 0.18), in: Circle())
                                    .overlay(Circle().strokeBorder(Color.white.opacity(0.25), lineWidth: 0.7))
                            }
                        }

                        VStack(alignment: .leading, spacing: 1) {
                            Text("AI Provider Launchpad (\(vm.currentMachine.name))")
                                .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                            Text(vm.isLaunchpadExpanded ? "Tap any LobeHub provider to launch" : "10 authenticated AI CLIs • Tap to expand")
                                .font(.system(size: 10.5, weight: .medium, design: .rounded))
                                .foregroundColor(.white.opacity(0.55))
                        }

                        Spacer()

                        HStack(spacing: 4) {
                            Text(vm.isLaunchpadExpanded ? "Hide" : "Expand")
                                .font(.system(size: 11, weight: .bold, design: .rounded))
                            Image(systemName: vm.isLaunchpadExpanded ? "chevron.up" : "chevron.down")
                                .font(.system(size: 11, weight: .bold))
                        }
                        .foregroundColor(.cyan)
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(Color.cyan.opacity(0.14), in: Capsule())
                    }
                    .padding(12)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)

                if vm.isLaunchpadExpanded {
                    Divider()
                        .background(Color.white.opacity(0.12))
                        .padding(.horizontal, 12)

                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 9), GridItem(.flexible(), spacing: 9)], spacing: 9) {
                        ForEach(providers) { item in
                            Button {
                                vm.runCommandOnSelectedMachine("", action: item.id)
                            } label: {
                                HStack(spacing: 9) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 11, style: .continuous)
                                            .fill(
                                                LinearGradient(
                                                    colors: [item.glow.opacity(0.26), Color.white.opacity(0.05)],
                                                    startPoint: .topLeading,
                                                    endPoint: .bottomTrailing
                                                )
                                            )
                                            .frame(width: 38, height: 38)
                                            .overlay(LiquidSpecularBorder(cornerRadius: 11, tint: item.glow))

                                        Image(item.assetName)
                                            .resizable()
                                            .scaledToFit()
                                            .frame(width: 22, height: 22)
                                    }

                                    VStack(alignment: .leading, spacing: 1) {
                                        Text(item.title)
                                            .font(.system(size: 12.5, weight: .bold, design: .rounded))
                                            .foregroundColor(.white)
                                            .lineLimit(1)
                                        Text(item.flag)
                                            .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                                            .foregroundColor(item.glow.opacity(0.95))
                                            .lineLimit(1)
                                    }
                                    Spacer(minLength: 0)
                                }
                                .padding(9)
                                .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 15, style: .continuous))
                                .overlay(LiquidSpecularBorder(cornerRadius: 15, tint: item.glow))
                            }
                            .buttonStyle(LiquidSpringButtonStyle())
                        }
                    }
                    .padding(12)
                    .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }
        }
    }

    // MARK: - Live Display Studio Card (alberto-dev X11 Desktop)

    private var liveDisplayStudioCard: some View {
        LiquidGlassSurface(cornerRadius: 22, tint: .indigo) {
            VStack(spacing: 0) {
                HStack(spacing: 7) {
                    Circle().fill(Color(red: 1.0, green: 0.37, blue: 0.34)).frame(width: 8, height: 8)
                    Circle().fill(Color(red: 1.0, green: 0.74, blue: 0.18)).frame(width: 8, height: 8)
                    Circle().fill(Color(red: 0.15, green: 0.79, blue: 0.25)).frame(width: 8, height: 8)

                    Text("alberto-dev • DISPLAY :1")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(.white.opacity(0.8))

                    Spacer()

                    Button {
                        vm.triggerX11Action("desktop:tile")
                    } label: {
                        Label("Tile", systemImage: "rectangle.grid.2x2")
                            .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.white.opacity(0.10), in: Capsule())
                    }

                    Menu {
                        ForEach(MonitorClickMode.allCases) { mode in
                            Button {
                                vm.clickMode = mode
                            } label: {
                                Label(mode.rawValue, systemImage: vm.clickMode == mode ? "checkmark.circle.fill" : "hand.tap")
                            }
                        }
                    } label: {
                        Text(vm.clickMode.rawValue)
                            .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                            .foregroundColor(.cyan)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.cyan.opacity(0.14), in: Capsule())
                    }

                    Button {
                        vm.useInteractiveWebVNC.toggle()
                    } label: {
                        Text(vm.useInteractiveWebVNC ? "Native" : "WebVNC")
                            .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.white.opacity(0.10), in: Capsule())
                    }

                    Button {
                        showFullscreenMonitor = true
                    } label: {
                        Image(systemName: "arrow.up.left.and.arrow.down.right")
                            .font(.system(size: 10.5, weight: .bold))
                            .foregroundColor(.white)
                            .frame(width: 25, height: 25)
                            .background(Color.white.opacity(0.10), in: Circle())
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.black.opacity(0.30))

                ZStack {
                    Color(red: 0.01, green: 0.02, blue: 0.04)

                    if vm.useInteractiveWebVNC,
                       let vncURL = URL(string: "\(vm.activeEndpoint)/novnc/vnc.html?autoconnect=true&resize=scale&reconnect=true&path=websockify") {
                        WebViewContainer(url: vncURL)
                    } else if let img = vm.screenImage {
                        GeometryReader { geo in
                            ZStack {
                                Image(uiImage: img)
                                    .resizable()
                                    .aspectRatio(contentMode: .fit)
                                    .frame(width: geo.size.width, height: geo.size.height)
                                    .contentShape(Rectangle())
                                    .gesture(
                                        DragGesture(minimumDistance: 0)
                                            .onEnded { value in
                                                guard let norm = FittedImageGeometry.normalizedPoint(
                                                    location: value.location,
                                                    in: geo.size,
                                                    imageSize: img.size
                                                ) else { return }
                                                animateTapRipple(at: value.location)
                                                vm.triggerX11Action(vm.clickMode.actionName, arg: String(format: "%.4f,%.4f", norm.x, norm.y))
                                            }
                                    )

                                if let pt = tapRipplePoint {
                                    Circle()
                                        .strokeBorder(Color.cyan, lineWidth: 2)
                                        .background(Circle().fill(Color.cyan.opacity(0.22)))
                                        .frame(width: 32, height: 32)
                                        .scaleEffect(tapRippleScale)
                                        .opacity(tapRippleOpacity)
                                        .position(pt)
                                        .allowsHitTesting(false)
                                }
                            }
                        }
                    } else {
                        ProgressView("Streaming DISPLAY :1...")
                            .tint(.cyan)
                            .foregroundColor(.white.opacity(0.7))
                    }
                }
                .frame(height: 215)

                if let wins = vm.currentMachine.windows, !wins.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            Text("WINDOWS")
                                .font(.system(size: 9, weight: .heavy, design: .monospaced))
                                .foregroundColor(.white.opacity(0.45))

                            ForEach(wins) { win in
                                Button {
                                    vm.triggerX11Action("desktop:focus", arg: win.id)
                                } label: {
                                    HStack(spacing: 4) {
                                        Image(systemName: "macwindow")
                                            .font(.system(size: 10))
                                            .foregroundColor(.cyan)
                                        Text(win.title)
                                            .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                                            .foregroundColor(.white.opacity(0.88))
                                            .lineLimit(1)
                                    }
                                    .padding(.horizontal, 9)
                                    .padding(.vertical, 4)
                                    .background(Color.white.opacity(0.08), in: Capsule())
                                }
                                .buttonStyle(LiquidSpringButtonStyle())
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 7)
                    }
                    .background(Color.black.opacity(0.26))
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        }
    }

    // MARK: - Mac Fleet Hardware Overview Card

    private var macHardwareOverviewCard: some View {
        let m = vm.currentMachine
        return LiquidGlassSurface(cornerRadius: 22, tint: .cyan) {
            VStack(alignment: .leading, spacing: 11) {
                HStack(spacing: 12) {
                    Image(systemName: iconForMachine(m))
                        .font(.system(size: 24, weight: .semibold))
                        .foregroundColor(.cyan)
                        .frame(width: 48, height: 48)
                        .background(Color.cyan.opacity(0.15), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .overlay(LiquidSpecularBorder(cornerRadius: 14, tint: .cyan))

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(m.name)
                                .font(.system(size: 16, weight: .heavy, design: .rounded))
                                .foregroundColor(.white)
                            Text(m.online ? "ONLINE" : "OFFLINE")
                                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                .foregroundColor(m.online ? .green : .red)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background((m.online ? Color.green : Color.red).opacity(0.14), in: Capsule())
                        }
                        Text("\(m.chip) • \(m.os)")
                            .font(.system(size: 12, weight: .semibold, design: .rounded))
                            .foregroundColor(.white.opacity(0.75))
                        Text(m.ip)
                            .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                            .foregroundColor(.cyan.opacity(0.85))
                    }
                    Spacer()
                }

                HStack(spacing: 7) {
                    ForEach(quickDiagnosticCommands, id: \.label) { item in
                        if ["System Info", "Top CPU", "Disk Space", "Git Status"].contains(item.label) {
                            Button {
                                vm.runCommandOnSelectedMachine(item.cmd)
                            } label: {
                                Text(item.label)
                                    .font(.system(size: 10.5, weight: .bold, design: .rounded))
                                    .foregroundColor(.white)
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 7)
                                    .background(Color.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                                    .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.white.opacity(0.16), lineWidth: 0.7))
                            }
                            .buttonStyle(LiquidSpringButtonStyle())
                        }
                    }
                }
            }
            .padding(14)
        }
    }

    // MARK: - Live Interactive Terminal Console Card

    private func liveTerminalConsoleCard(compact: Bool) -> some View {
        let m = vm.currentMachine
        return LiquidGlassSurface(cornerRadius: 22, tint: .mint) {
            VStack(alignment: .leading, spacing: 9) {
                HStack {
                    HStack(spacing: 6) {
                        Image(systemName: "terminal.fill")
                            .font(.system(size: 12, weight: .bold))
                            .foregroundColor(.mint)
                        Text("LIVE SHELL CONSOLE — \(m.name.uppercased())")
                            .font(.system(size: 11, weight: .heavy, design: .monospaced))
                            .foregroundColor(.white.opacity(0.82))
                    }
                    Spacer()
                    if vm.isRunningCommand {
                        ProgressView()
                            .scaleEffect(0.75)
                            .tint(.cyan)
                    }
                    Button {
                        UIPasteboard.general.string = m.terminal_log
                        vm.presentToast("Copied terminal output")
                    } label: {
                        Label("Copy", systemImage: "doc.on.doc")
                            .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                            .foregroundColor(.white.opacity(0.8))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(Color.white.opacity(0.08), in: Capsule())
                    }
                }

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(quickDiagnosticCommands, id: \.label) { item in
                            Button {
                                vm.runCommandOnSelectedMachine(item.cmd)
                            } label: {
                                HStack(spacing: 4) {
                                    Image(systemName: "play.fill")
                                        .font(.system(size: 8.5))
                                        .foregroundColor(.mint)
                                    Text(item.label)
                                        .font(.system(size: 10.5, weight: .semibold, design: .rounded))
                                        .foregroundColor(.white)
                                }
                                .padding(.horizontal, 9)
                                .padding(.vertical, 5)
                                .background(Color.mint.opacity(0.12), in: Capsule())
                                .overlay(Capsule().strokeBorder(Color.mint.opacity(0.30), lineWidth: 0.7))
                            }
                            .buttonStyle(LiquidSpringButtonStyle())
                        }
                    }
                }

                ScrollView(.vertical, showsIndicators: true) {
                    Text(m.terminal_log.isEmpty ? "$ Ready on \(m.name)" : m.terminal_log)
                        .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                        .foregroundColor(Color(red: 0.85, green: 0.96, blue: 0.90))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                        .padding(10)
                }
                .frame(height: compact ? 145 : 310)
                .background(Color.black.opacity(0.45), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.10), lineWidth: 0.8)
                )
            }
            .padding(13)
        }
    }

    // MARK: - Processes & Active Windows Card

    private var processesAndWindowsCard: some View {
        let m = vm.currentMachine
        return LiquidGlassSurface(cornerRadius: 22, tint: .purple) {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("TOP PROCESSES — \(m.name.uppercased())")
                        .font(.system(size: 11, weight: .heavy, design: .rounded))
                        .foregroundColor(.white.opacity(0.78))
                    Spacer()
                    Text("LOAD \(String(format: "%.2f", m.load_1m))")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(.purple)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.purple.opacity(0.16), in: Capsule())
                }

                ForEach(m.top_processes) { proc in
                    HStack(spacing: 10) {
                        Text(proc.pid)
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(.white.opacity(0.48))
                            .frame(width: 46, alignment: .leading)

                        Text(proc.name)
                            .font(.system(size: 12, weight: .bold, design: .monospaced))
                            .foregroundColor(.white)
                            .lineLimit(1)

                        Spacer()

                        Text(String(format: "%.1f%% CPU", proc.cpu))
                            .font(.system(size: 11, weight: .bold, design: .monospaced))
                            .foregroundColor(.cyan)

                        Text(String(format: "%.1f%% MEM", proc.mem))
                            .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                            .foregroundColor(.white.opacity(0.62))
                            .frame(width: 68, alignment: .trailing)
                    }
                    .padding(.horizontal, 10)
                    .padding(.vertical, 7)
                    .background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                }
            }
            .padding(14)
        }
    }

    // MARK: - Cloud VMs Fleet Card (All 7 cmux VMs)

    private var cloudVMsFleetCard: some View {
        LiquidGlassSurface(cornerRadius: 22, tint: .cyan) {
            VStack(alignment: .leading, spacing: 11) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("CMUX CLOUD VM FLEET")
                            .font(.system(size: 11, weight: .heavy, design: .rounded))
                            .foregroundColor(.white.opacity(0.78))
                        Text("All active team cloud machines • Tap to inspect or snapshot")
                            .font(.system(size: 10.5, weight: .medium, design: .rounded))
                            .foregroundColor(.white.opacity(0.5))
                    }
                    Spacer()
                    Text("\(vm.cloudVMs.count) RUNNING")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(.green)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Color.green.opacity(0.14), in: Capsule())
                }

                ForEach(vm.cloudVMs) { item in
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                HStack(spacing: 6) {
                                    Circle()
                                        .fill(item.state == "running" ? Color.green : Color.orange)
                                        .frame(width: 7, height: 7)
                                    Text(item.label)
                                        .font(.system(size: 13, weight: .bold, design: .rounded))
                                        .foregroundColor(.white)
                                        .lineLimit(1)
                                }
                                Text("\(item.id) • \(item.image)")
                                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                                    .foregroundColor(.white.opacity(0.52))
                                    .lineLimit(1)
                            }
                            Spacer()
                            Button {
                                vm.runCommandOnSelectedMachine("uname -a && uptime && df -h /", targetOverride: item.id)
                                vm.activeTab = .terminal
                            } label: {
                                Label("Inspect", systemImage: "terminal")
                                    .font(.system(size: 10.5, weight: .bold, design: .rounded))
                                    .foregroundColor(.cyan)
                                    .padding(.horizontal, 9)
                                    .padding(.vertical, 5)
                                    .background(Color.cyan.opacity(0.14), in: Capsule())
                            }
                            .buttonStyle(LiquidSpringButtonStyle())

                            if item.label == "alberto-dev" {
                                Button {
                                    vm.runCommandOnSelectedMachine("snapshot", targetOverride: item.id, action: "vm:snapshot")
                                } label: {
                                    Label("Save", systemImage: "camera.aperture")
                                        .font(.system(size: 10.5, weight: .bold, design: .rounded))
                                        .foregroundColor(.mint)
                                        .padding(.horizontal, 9)
                                        .padding(.vertical, 5)
                                        .background(Color.mint.opacity(0.14), in: Capsule())
                                }
                                .buttonStyle(LiquidSpringButtonStyle())
                            }
                        }
                    }
                    .padding(11)
                    .background(Color.white.opacity(0.045), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Color.white.opacity(0.10), lineWidth: 0.8))
                }
            }
            .padding(14)
        }
    }

    private func animateTapRipple(at point: CGPoint) {
        tapRipplePoint = point
        tapRippleScale = 0.35
        tapRippleOpacity = 0.95
        withAnimation(.easeOut(duration: 0.42)) {
            tapRippleScale = 1.45
            tapRippleOpacity = 0.0
        }
    }

    // MARK: - Floating Liquid Glass Command Dock

    private var floatingCommandDock: some View {
        LiquidGlassSurface(cornerRadius: 24, tint: .cyan) {
            VStack(spacing: 7) {
                if vm.selectedMachineID == "alberto-dev" {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(quickKeys, id: \.key) { item in
                                Button {
                                    vm.triggerX11Action("desktop:key", arg: item.key)
                                } label: {
                                    Text(item.label)
                                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                                        .foregroundColor(.white)
                                        .padding(.horizontal, 10)
                                        .padding(.vertical, 5)
                                        .background(Color.white.opacity(0.09), in: Capsule())
                                        .overlay(Capsule().strokeBorder(Color.white.opacity(0.20), lineWidth: 0.7))
                                }
                                .buttonStyle(LiquidSpringButtonStyle())
                            }
                        }
                    }
                }

                HStack(spacing: 8) {
                    HStack(spacing: 4) {
                        Image(systemName: iconForMachine(vm.currentMachine))
                            .font(.system(size: 11, weight: .bold))
                            .foregroundColor(.cyan)
                        Text(vm.currentMachine.name)
                            .font(.system(size: 11, weight: .bold, design: .rounded))
                            .foregroundColor(.cyan)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(Color.cyan.opacity(0.14), in: Capsule())

                    TextField("Run on \(vm.currentMachine.name)...", text: $customCommand)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.white)
                        .submitLabel(.send)
                        .onSubmit {
                            submitCustomCommand()
                        }

                    Button {
                        submitCustomCommand()
                    } label: {
                        Text("Run")
                            .font(.system(size: 12, weight: .bold, design: .rounded))
                            .foregroundColor(.white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 7)
                            .background(
                                LinearGradient(
                                    colors: [Color.indigo, Color.cyan],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                ),
                                in: Capsule()
                            )
                            .overlay(Capsule().strokeBorder(Color.white.opacity(0.35), lineWidth: 0.8))
                    }
                    .buttonStyle(LiquidSpringButtonStyle())
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 9)
        }
    }

    private func submitCustomCommand() {
        let trimmed = customCommand.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        vm.runCommandOnSelectedMachine(trimmed)
        customCommand = ""
    }
}

// MARK: - Fullscreen Pinch-to-Zoom Studio Sheet

struct FullscreenGlassDisplaySheet: View {
    @ObservedObject var vm: CloudStudioViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var zoom: CGFloat = 1.0

    var body: some View {
        ZStack(alignment: .top) {
            Color.black.ignoresSafeArea()

            if let img = vm.screenImage {
                GeometryReader { geo in
                    ScrollView([.horizontal, .vertical], showsIndicators: false) {
                        Image(uiImage: img)
                            .resizable()
                            .aspectRatio(contentMode: .fit)
                            .frame(width: geo.size.width * zoom, height: geo.size.height * zoom)
                            .gesture(
                                SpatialTapGesture()
                                    .onEnded { event in
                                        let frameSize = CGSize(width: geo.size.width * zoom, height: geo.size.height * zoom)
                                        guard let norm = FittedImageGeometry.normalizedPoint(
                                            location: event.location,
                                            in: frameSize,
                                            imageSize: img.size
                                        ) else { return }
                                        vm.triggerX11Action(vm.clickMode.actionName, arg: String(format: "%.4f,%.4f", norm.x, norm.y))
                                    }
                            )
                    }
                }
            } else {
                ProgressView("Streaming DISPLAY :1...")
                    .tint(.cyan)
                    .foregroundColor(.white)
            }

            HStack(spacing: 10) {
                Button {
                    dismiss()
                } label: {
                    Label("Back", systemImage: "chevron.down.circle.fill")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 8)
                        .background(.ultraThinMaterial, in: Capsule())
                        .overlay(Capsule().strokeBorder(Color.white.opacity(0.28), lineWidth: 1))
                }

                Spacer()

                Button {
                    vm.triggerX11Action("desktop:tile")
                } label: {
                    Label("Tile 1440×900", systemImage: "rectangle.grid.2x2")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundColor(.white)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(.ultraThinMaterial, in: Capsule())
                        .overlay(Capsule().strokeBorder(Color.white.opacity(0.25), lineWidth: 1))
                }

                Button {
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.78)) {
                        zoom = zoom == 1.0 ? 1.85 : 1.0
                    }
                } label: {
                    Label(zoom == 1.0 ? "1.85×" : "1.0×", systemImage: "plus.magnifyingglass")
                        .font(.system(size: 12, weight: .bold, design: .rounded))
                        .foregroundColor(.cyan)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .background(.ultraThinMaterial, in: Capsule())
                        .overlay(Capsule().strokeBorder(Color.cyan.opacity(0.35), lineWidth: 1))
                }
            }
            .padding()
        }
    }
}

// MARK: - Interactive WebView VNC Container

struct WebViewContainer: UIViewRepresentable {
    let url: URL
    var authToken: String? = nil

    private func makeAuthorizedRequest(for targetURL: URL) -> URLRequest {
        var req = URLRequest(url: targetURL)
        if let token = authToken ?? KeychainTokenStore.loadToken(for: targetURL), !token.isEmpty {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeUIView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true
        config.preferences.javaScriptCanOpenWindowsAutomatically = false
        let webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = context.coordinator
        webView.isOpaque = false
        webView.backgroundColor = .black
        webView.scrollView.backgroundColor = .black
        context.coordinator.lastURL = url
        webView.load(makeAuthorizedRequest(for: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        if context.coordinator.lastURL != url {
            context.coordinator.lastURL = url
            webView.load(makeAuthorizedRequest(for: url))
        }
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var lastURL: URL?

        private static func effectivePort(for url: URL) -> Int? {
            if let port = url.port { return port }
            switch url.scheme?.lowercased() {
            case "https": return 443
            case "http": return 80
            default: return nil
            }
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            guard let targetURL = navigationAction.request.url,
                  let expectedURL = lastURL,
                  let expectedHost = expectedURL.host?.lowercased(),
                  let targetHost = targetURL.host?.lowercased(),
                  targetHost == expectedHost,
                  targetURL.scheme?.lowercased() == expectedURL.scheme?.lowercased(),
                  Self.effectivePort(for: targetURL) == Self.effectivePort(for: expectedURL) else {
                decisionHandler(.cancel)
                return
            }
            let scheme = targetURL.scheme?.lowercased() ?? ""
            if scheme == "https" {
                decisionHandler(.allow)
                return
            }
            #if DEBUG
            if scheme == "http" && TLSTrustEvaluator.isLoopbackHost(targetHost) {
                decisionHandler(.allow)
                return
            }
            #endif
            decisionHandler(.cancel)
        }

        func webView(
            _ webView: WKWebView,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            TLSTrustEvaluator.evaluate(challenge: challenge, completionHandler: completionHandler)
        }
    }
}

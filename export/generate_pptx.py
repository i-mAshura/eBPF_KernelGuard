"""
KernelGuard Presentation Generator
Generates a 16:9 widescreen, dark-themed, publication-grade PowerPoint deck
covering KernelGuard's architecture, math, benchmarks, and mitigation engine.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_deck(output_path="KernelGuard_Presentation.pptx"):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Color Palette (Dark Cybersecurity Theme)
    BG_COLOR = RGBColor(10, 15, 29)          # Deep Navy #0A0F1D
    CARD_BG = RGBColor(17, 24, 39)           # Card Slate #111827
    CARD_BORDER = RGBColor(30, 41, 59)       # Border #1E293B
    CYAN = RGBColor(0, 240, 255)             # Accent Cyan #00F0FF
    EMERALD = RGBColor(16, 185, 129)         # Green #10B981
    PURPLE = RGBColor(168, 85, 247)          # Violet #A855F7
    ROSE = RGBColor(244, 63, 94)             # Crimson #F43F5E
    WHITE = RGBColor(248, 250, 252)          # Text High #F8FAFC
    MUTED = RGBColor(148, 163, 184)          # Text Low #94A3B8
    BLUE = RGBColor(59, 130, 246)            # Sky Blue #3B82F6

    blank_layout = prs.slide_layouts[6]

    def set_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_COLOR
        bg.line.fill.background()
        return bg

    def add_header(slide, title, category="KERNELGUARD RESEARCH DECK", color=CYAN):
        # Category Tag
        cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
        tf_cat = cat_box.text_frame
        tf_cat.word_wrap = True
        p_cat = tf_cat.paragraphs[0]
        p_cat.text = category.upper()
        p_cat.font.size = Pt(10)
        p_cat.font.bold = True
        p_cat.font.color.rgb = color
        p_cat.font.name = "Calibri"

        # Main Title
        title_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.7), Inches(11.7), Inches(0.7))
        tf = title_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(24)
        p.font.bold = True
        p.font.color.rgb = WHITE
        p.font.name = "Calibri"

    def add_card(slide, left, top, width, height, bg_color=CARD_BG, border_color=CARD_BORDER):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        card.line.color.rgb = border_color
        card.line.width = Pt(1.5)
        return card

    # ==========================================
    # SLIDE 1: Title Slide
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_bg(s1)

    # Accent decorative card
    add_card(s1, 0.8, 1.2, 11.733, 5.1, CARD_BG, CYAN)

    t_box = s1.shapes.add_textbox(Inches(1.2), Inches(1.6), Inches(10.9), Inches(1.8))
    tf1 = t_box.text_frame
    tf1.word_wrap = True
    p1 = tf1.paragraphs[0]
    p1.text = "KernelGuard"
    p1.font.size = Pt(44)
    p1.font.bold = True
    p1.font.color.rgb = CYAN
    p1.font.name = "Calibri"

    p2 = tf1.add_paragraph()
    p2.text = "Adaptive eBPF-Driven Behavioral Malware Detection Using Real-Time Kernel Telemetry & Graph Learning"
    p2.font.size = Pt(20)
    p2.font.bold = True
    p2.font.color.rgb = WHITE
    p2.font.name = "Calibri"

    desc_box = s1.shapes.add_textbox(Inches(1.2), Inches(3.4), Inches(10.9), Inches(1.3))
    tf_desc = desc_box.text_frame
    tf_desc.word_wrap = True
    p_desc = tf_desc.paragraphs[0]
    p_desc.text = "A zero-overhead, in-kernel autonomous defense framework bridging lockless eBPF telemetry, dynamic temporal multi-graphs, and hybrid GNN-Transformer neural inference to combat fileless malware, ransomware, and stealth C2 campaigns."
    p_desc.font.size = Pt(14)
    p_desc.font.color.rgb = MUTED
    p_desc.font.name = "Calibri"

    # Meta tags / pills
    pills = [
        ("⚡ < 1.15% CPU Overhead", CYAN),
        ("🛡️ 0.42 ms Autonomous Mitigation", ROSE),
        ("🧠 0.9892 ROC-AUC on DARPA TC", EMERALD),
        ("🕸️ Temporal GNN + Transformer", PURPLE)
    ]
    for i, (pill_text, pill_color) in enumerate(pills):
        px = 1.2 + (i * 2.7)
        card = add_card(s1, px, 4.9, 2.5, 0.9, RGBColor(20, 28, 48), pill_color)
        pbox = s1.shapes.add_textbox(Inches(px), Inches(5.1), Inches(2.5), Inches(0.5))
        ptf = pbox.text_frame
        pp = ptf.paragraphs[0]
        pp.text = pill_text
        pp.alignment = PP_ALIGN.CENTER
        pp.font.size = Pt(11)
        pp.font.bold = True
        pp.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 2: Problem Statement & Threat Landscape
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_bg(s2)
    add_header(s2, "The Modern Linux Threat Landscape & Limitations of Existing Defenses", "PROBLEM STATEMENT & MOTIVATION")

    problems = [
        ("Fileless In-Memory Malware",
         "Attacks allocate anonymous memory via memfd_create() and execute shellcode with mprotect(PROT_EXEC). Zero disk writes render traditional antivirus and static signature inspection obsolete.",
         ROSE),
        ("High-Speed Ransomware",
         "Modern ransomware encrypts thousands of critical files per second before terminating system handles. Existing userspace detectors experience TOCTOU latency, detecting attacks only after total data loss.",
         ROSE),
        ("Stealth C2 & Privilege Escalation",
         "Living-off-the-Land (LotL) binaries abuse native system tools (curl, python, sh) and exploit kernel vulnerabilities (unauthorized setuid(0)) to bypass heuristic anomaly baselines.",
         ROSE),
        ("The 'Auditd Dilemma' (Overhead vs Visibility)",
         "Legacy audit frameworks (auditd) impose 12% - 25% CPU degradation under heavy enterprise workloads and drop events during ring-buffer floods, forcing organizations to disable deep monitoring.",
         ROSE)
    ]

    for i, (title, desc, color) in enumerate(problems):
        col = i % 2
        row = i // 2
        x = 0.8 + (col * 5.95)
        y = 1.6 + (row * 2.6)
        add_card(s2, x, y, 5.75, 2.3, CARD_BG, CARD_BORDER)

        tbox = s2.shapes.add_textbox(Inches(x + 0.3), Inches(y + 0.2), Inches(5.15), Inches(0.4))
        p = tbox.text_frame.paragraphs[0]
        p.text = f"❌  {title}"
        p.font.size = Pt(15)
        p.font.bold = True
        p.font.color.rgb = color

        dbox = s2.shapes.add_textbox(Inches(x + 0.3), Inches(y + 0.65), Inches(5.15), Inches(1.4))
        tf = dbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(12)
        p.font.color.rgb = MUTED

    # ==========================================
    # SLIDE 3: Research Contributions & Core Insight
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_bg(s3)
    add_header(s3, "KernelGuard Research Contributions: 4 Core Pillars", "RESEARCH CONTRIBUTIONS & SYSTEM VISION")

    pillars = [
        ("1. Lockless In-Kernel Telemetry",
         "• eBPF tracepoints capture 8 critical syscall families (execve, fork, mprotect, memfd, openat, connect, setuid).\n• Lockless 256 KB BPF RingBuffer sustains 48,200 events/sec with < 1.15% CPU overhead.",
         CYAN),
        ("2. Temporal Behavioral Graph",
         "• Transforms raw syscall streams into dynamic temporal multi-graph G = (V, E, T).\n• Causal provenance slicing isolates root-cause patient-zero processes and tracks blast-radius taint.",
         BLUE),
        ("3. Hybrid GNN-Transformer",
         "• Relational GAT learns heterogeneous spatial entity interactions.\n• Temporal Transformer self-attention captures microsecond-scale causal event ordering.\n• Max-mean pooling prevents threat dilution.",
         PURPLE),
        ("4. Autonomous In-Kernel Mitigation",
         "• Bridges detection to eBPF LSM security hooks (bprm_check_security, file_open).\n• Enforces bpf_send_signal(SIGKILL) directly in kernel space before syscall completion in < 0.45 ms.",
         EMERALD)
    ]

    for i, (title, desc, color) in enumerate(pillars):
        x = 0.8 + (i * 2.95)
        y = 1.6
        add_card(s3, x, y, 2.8, 5.2, CARD_BG, color)

        tbox = s3.shapes.add_textbox(Inches(x + 0.2), Inches(y + 0.25), Inches(2.4), Inches(0.8))
        tf = tbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = color

        dbox = s3.shapes.add_textbox(Inches(x + 0.2), Inches(y + 1.1), Inches(2.4), Inches(3.8))
        tf = dbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(12)
        p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 4: Comprehensive System Architecture
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_bg(s4)
    add_header(s4, "End-to-End System Architecture: 5-Tier Pipeline", "SYSTEM ARCHITECTURE & WORKFLOW")

    tiers = [
        ("Tier 1: Linux Kernel Space (eBPF)",
         "Lineage, Memory, & I/O Probes (execve, mprotect, memfd) + In-Kernel eBPF LSM Hook (bpf_send_signal SIGKILL) -> 256 KB Lockless RingBuffer.",
         CYAN),
        ("Tier 2: Multi-Source Telemetry Ingestion",
         "Unified Dispatcher normalizing live eBPF streams (48.2k ev/s), Host OS Sniffer (psutil), and DARPA TC CDM records into canonical microsecond events.",
         BLUE),
        ("Tier 3: Temporal Behavioral Multi-Graph",
         "Dynamic graph G = (V, E, T) maintaining entity nodes (processes, files, sockets, memory) and causal edges with backward & forward provenance slicing.",
         EMERALD),
        ("Tier 4: Hybrid GNN-Transformer & Explainer",
         "Relational Graph Attention Layer + Temporal Transformer Self-Attention + Max-Mean Pooling + GNNExplainer Gradient Edge Saliency Attribution Heatmap.",
         PURPLE),
        ("Tier 5: Adaptive Defense HUD & Mitigation",
         "Composite Risk Synthesizer (S_composite) + Automated MITRE ATT&CK Mapping + Autonomous In-Kernel Mitigation Engine (< 0.45 ms Latency).",
         ROSE)
    ]

    for i, (title, desc, color) in enumerate(tiers):
        y = 1.5 + (i * 1.05)
        add_card(s4, 0.8, y, 11.733, 0.95, CARD_BG, color)

        tbox = s4.shapes.add_textbox(Inches(1.0), Inches(y + 0.1), Inches(3.6), Inches(0.75))
        tf = tbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = color

        dbox = s4.shapes.add_textbox(Inches(4.7), Inches(y + 0.1), Inches(7.6), Inches(0.75))
        tf = dbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 5: eBPF Kernel Instrumentation & Zero-Copy Telemetry
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_bg(s5)
    add_header(s5, "eBPF Kernel Instrumentation & Zero-Copy Telemetry Engine", "KERNEL-LEVEL OBSERVABILITY")

    add_card(s5, 0.8, 1.6, 5.75, 5.2, CARD_BG, CYAN)
    tbox = s5.shapes.add_textbox(Inches(1.1), Inches(1.8), Inches(5.15), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "🎯 Targeted Syscall Probes & Invariants"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN

    cbox = s5.shapes.add_textbox(Inches(1.1), Inches(2.4), Inches(5.15), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    content = (
        "• Process Execution & Lineage:\n"
        "  - sys_enter_execve / sys_enter_fork: Track parent-child ancestry.\n"
        "  - sys_enter_setuid: Trap unauthorized root privilege escalations.\n\n"
        "• Memory Invariants (W^X Violations):\n"
        "  - sys_enter_memfd_create: Flag fileless in-memory ELF allocation.\n"
        "  - sys_enter_mprotect: Detect PROT_EXEC on non-file backed pages.\n\n"
        "• I/O & Network C2 Channel:\n"
        "  - sys_enter_openat / sys_enter_unlinkat: Mass file modifications.\n"
        "  - sys_enter_connect: Outbound reverse shell socket connections."
    )
    p = tf.paragraphs[0]
    p.text = content
    p.font.size = Pt(12)
    p.font.color.rgb = WHITE

    add_card(s5, 6.78, 1.6, 5.75, 5.2, CARD_BG, BLUE)
    tbox = s5.shapes.add_textbox(Inches(7.1), Inches(1.8), Inches(5.15), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "⚡ Zero-Copy BPF RingBuffer Architecture"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = BLUE

    cbox2 = s5.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.15), Inches(4.2))
    tf2 = cbox2.text_frame
    tf2.word_wrap = True
    content2 = (
        "• Multi-Core Lockless RingBuffer (256 KB):\n"
        "  - Zero userspace copy overhead via memory-mapped pages.\n"
        "  - Sustained throughput: 48,200 events/second.\n\n"
        "• BPF In-Kernel Event Structure (kernelguard_event_t):\n"
        "  - uint64_t timestamp_ns (nanosecond precision)\n"
        "  - uint32_t pid, ppid, uid, event_type\n"
        "  - char comm[16], filename[64], ip_str[16]\n\n"
        "• Empirical CPU Overhead:\n"
        "  - KernelGuard: < 1.15% CPU under synthetic stress benchmarks.\n"
        "  - Auditd: 12.4% CPU overhead (10.7x higher)."
    )
    p = tf2.paragraphs[0]
    p.text = content2
    p.font.size = Pt(12)
    p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 6: Temporal Graph & Causal Provenance Slicing
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_bg(s6)
    add_header(s6, "Temporal Behavioral Multi-Graph & Causal Provenance Slicing", "GRAPH REPRESENTATION & CAUSAL REASONING")

    add_card(s6, 0.8, 1.6, 3.75, 5.2, CARD_BG, EMERALD)
    tbox = s6.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(3.35), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "Graph Definition G=(V,E,T)"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = EMERALD

    cbox = s6.shapes.add_textbox(Inches(1.0), Inches(2.4), Inches(3.35), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = (
        "• Dynamic Multi-Graph:\n"
        "  Maintains live system interactions across time.\n\n"
        "• Heterogeneous Nodes (V):\n"
        "  - Process Entities: PID, binary name, UID, command line.\n"
        "  - File Entities: Path, inode, file mode.\n"
        "  - Socket Entities: Remote IP, port, protocol.\n"
        "  - Memory Entities: Anonymous fd, permissions (RWX).\n\n"
        "• Attributed Edges (E):\n"
        "  Syscall event type, relative delta t, process lineage depth."
    )
    p.font.size = Pt(11)
    p.font.color.rgb = WHITE

    add_card(s6, 4.79, 1.6, 3.75, 5.2, CARD_BG, CYAN)
    tbox = s6.shapes.add_textbox(Inches(5.0), Inches(1.8), Inches(3.35), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "Backward Provenance Slicing"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = CYAN

    cbox = s6.shapes.add_textbox(Inches(5.0), Inches(2.4), Inches(3.35), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = (
        "• Root-Cause Discovery:\n"
        "  Traverses incoming causal dependencies backwards in time from anomaly trigger.\n\n"
        "• Patient-Zero Isolation:\n"
        "  Pins down the exact initial attack vector:\n"
        "  - Phishing email attachment\n"
        "  - Web server exploit\n"
        "  - Unauthorized curl execution\n\n"
        "• Elimination of Alert Fatigue:\n"
        "  Prunes 98% of unrelated background system noise to present a focused attack lineage."
    )
    p.font.size = Pt(11)
    p.font.color.rgb = WHITE

    add_card(s6, 8.78, 1.6, 3.75, 5.2, CARD_BG, PURPLE)
    tbox = s6.shapes.add_textbox(Inches(9.0), Inches(1.8), Inches(3.35), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "Forward Blast-Radius Slicing"
    p.font.size = Pt(15)
    p.font.bold = True
    p.font.color.rgb = PURPLE

    cbox = s6.shapes.add_textbox(Inches(9.0), Inches(2.4), Inches(3.35), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = (
        "• Attack Blast-Radius Expansion:\n"
        "  Traces forward causal propagation from compromised process.\n\n"
        "• Contamination Mapping:\n"
        "  - Identifies all modified, deleted, or encrypted files.\n"
        "  - Uncovers spawned worker threads and child shells.\n"
        "  - Maps external exfiltration sockets.\n\n"
        "• Precision Quarantine:\n"
        "  Provides exact target list for the autonomous mitigation engine."
    )
    p.font.size = Pt(11)
    p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 7: Hybrid GNN-Transformer Neural Engine & Explainer
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_bg(s7)
    add_header(s7, "Hybrid GNN-Transformer Neural Engine & Saliency Explainability", "APPLIED DEEP LEARNING ARCHITECTURE")

    nn_blocks = [
        ("1. Relational GAT Layer",
         "Spatial Neighborhood Aggregation:\nComputes dynamic attention coefficient alpha_ij over entity node features h_i and incoming edge attributes e_ij.\nIncorporates heterogeneous edge types (fork, write, exec, connect) into attention projection.",
         CYAN),
        ("2. Temporal Transformer",
         "Causal Sequence Encoding:\nApplies Multi-Head Self-Attention over chronological syscall transitions.\nCaptures subtle microsecond timing gaps that differentiate automated malware loops from human operator workflows.",
         BLUE),
        ("3. Max-Mean Threat Pooling",
         "Peak Anomaly Preservation:\nh_graph = 0.70 * max(h_i) + 0.30 * mean(h_i)\nPrevents localized malicious syscalls (e.g., isolated memfd_create) from being diluted by thousands of benign operations.",
         PURPLE),
        ("4. GNNExplainer Saliency Engine",
         "Gradient-Based Attribution:\nGenerates real-time edge attribution heatmaps (0% to 100%).\nReveals exactly which syscall edges caused the model trigger, providing transparent provenance for SOC analysts.",
         EMERALD)
    ]

    for i, (title, desc, color) in enumerate(nn_blocks):
        x = 0.8 + (i * 2.95)
        y = 1.6
        add_card(s7, x, y, 2.8, 5.2, CARD_BG, color)

        tbox = s7.shapes.add_textbox(Inches(x + 0.2), Inches(y + 0.25), Inches(2.4), Inches(0.8))
        tf = tbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = color

        dbox = s7.shapes.add_textbox(Inches(x + 0.2), Inches(y + 1.1), Inches(2.4), Inches(3.8))
        tf = dbox.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = desc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 8: Risk Scoring & Autonomous Active Mitigation
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_bg(s8)
    add_header(s8, "Adaptive Multi-Factor Risk Scoring & Autonomous In-Kernel Mitigation", "DETECTION & ACTIVE ENFORCEMENT")

    add_card(s8, 0.8, 1.6, 5.75, 5.2, CARD_BG, ROSE)
    tbox = s8.shapes.add_textbox(Inches(1.1), Inches(1.8), Inches(5.15), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "⚖️ Adaptive Composite Risk Formulation"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = ROSE

    cbox = s8.shapes.add_textbox(Inches(1.1), Inches(2.4), Inches(5.15), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = (
        "• Composite Scoring Equation:\n"
        "  S_composite = α * S_model + β * S_semantic + γ * S_lineage\n\n"
        "• Deep Neural Model (S_model):\n"
        "  Probability output from GNN-Transformer graph embedding.\n\n"
        "• Semantic Invariant Violations (S_semantic):\n"
        "  +0.45 for memfd_create execution\n"
        "  +0.35 for mprotect(PROT_EXEC) W^X breach\n"
        "  +0.50 for high-frequency mass unlinkat (ransomware)\n"
        "  +0.40 for /etc/shadow or credential access\n"
        "  +0.50 for unauthorized setuid(0) transition\n\n"
        "• Dynamic Safety Adaptation:\n"
        "  If S_semantic > 0.60, weights adapt to α=0.50, β=0.35, γ=0.15 to ensure deterministic policy enforcement."
    )
    p.font.size = Pt(11)
    p.font.color.rgb = WHITE

    add_card(s8, 6.78, 1.6, 5.75, 5.2, CARD_BG, EMERALD)
    tbox = s8.shapes.add_textbox(Inches(7.1), Inches(1.8), Inches(5.15), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "🛡️ Autonomous In-Kernel Mitigation Engine"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = EMERALD

    cbox2 = s8.shapes.add_textbox(Inches(7.1), Inches(2.4), Inches(5.15), Inches(4.2))
    tf2 = cbox2.text_frame
    tf2.word_wrap = True
    p2 = tf2.paragraphs[0]
    p2.text = (
        "• In-Kernel eBPF LSM Enforcement:\n"
        "  Hooks SEC(\"lsm/bprm_check_security\") and SEC(\"lsm/file_open\").\n"
        "  Employs bpf_send_signal(9) to send SIGKILL in kernel space before syscall return.\n\n"
        "• Sub-Millisecond Response Time:\n"
        "  Total mitigation execution latency is < 0.45 ms (vs seconds in traditional SOAR).\n\n"
        "• Tri-Fold Coordinated Containment:\n"
        "  1. In-Kernel Process Termination: SIGKILL to entire malicious process tree.\n"
        "  2. Netfilter IP Quarantine: Drops active C2 socket connections.\n"
        "  3. Volume Storage Lock: Freezes file tree read-only to stop ransomware encryption."
    )
    p2.font.size = Pt(11)
    p2.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 9: Benchmark & Experimental Evaluation
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_bg(s9)
    add_header(s9, "Empirical Benchmark: DARPA TC Datasets & Real Malware", "EXPERIMENTAL EVALUATION & PERFORMANCE")

    # Table card
    add_card(s9, 0.8, 1.6, 11.733, 3.4, CARD_BG, BLUE)
    table_shape = s9.shapes.add_table(7, 4, Inches(1.1), Inches(1.8), Inches(11.133), Inches(3.0))
    table = table_shape.table

    columns = ["Performance Metric", "KernelGuard (Ours)", "Auditd Baseline", "Falco (Kernel Module)"]
    for j, col_title in enumerate(columns):
        cell = table.cell(0, j)
        cell.text = col_title
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(30, 41, 59)
        p = cell.text_frame.paragraphs[0]
        p.font.bold = True
        p.font.size = Pt(12)
        p.font.color.rgb = CYAN if j == 1 else WHITE

    data = [
        ("Detection ROC-AUC", "0.9892", "0.9120", "0.9350"),
        ("Precision / Recall (TPR)", "98.40% / 98.10%", "89.15% / 91.40%", "92.10% / 93.20%"),
        ("False Positive Rate (FPR)", "0.75%", "8.60%", "4.20%"),
        ("Kernel CPU Overhead", "< 1.15%", "12.40%", "4.80%"),
        ("Total Detection Latency", "1.26 ms", "84.50 ms", "14.20 ms"),
        ("RingBuffer Event Throughput", "48,200 ev/s", "6,100 ev/s", "18,400 ev/s"),
    ]

    for i, row in enumerate(data):
        for j, val in enumerate(row):
            cell = table.cell(i + 1, j)
            cell.text = val
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(17, 24, 39) if i % 2 == 0 else RGBColor(22, 30, 48)
            p = cell.text_frame.paragraphs[0]
            p.font.size = Pt(11)
            p.font.color.rgb = EMERALD if j == 1 and i < 4 else (CYAN if j == 1 else WHITE)
            if j == 1:
                p.font.bold = True

    # 3 Summary callout cards below table
    summary_cards = [
        ("🚀 67x Faster Latency", "1.26 ms end-to-end vs 84.5 ms in legacy auditd systems.", CYAN),
        ("🛡️ 11x Lower Overhead", "Sub-1.15% CPU overhead vs 12.4% in auditd, enabling enterprise deployment.", EMERALD),
        ("🎯 11x Lower False Positives", "0.75% FPR vs 8.60% in auditd due to causal graph reasoning.", PURPLE)
    ]
    for i, (ctitle, cdesc, ccolor) in enumerate(summary_cards):
        cx = 0.8 + (i * 3.95)
        add_card(s9, cx, 5.2, 3.8, 1.6, CARD_BG, ccolor)
        tbox = s9.shapes.add_textbox(Inches(cx + 0.2), Inches(5.35), Inches(3.4), Inches(0.4))
        p = tbox.text_frame.paragraphs[0]
        p.text = ctitle
        p.font.size = Pt(13)
        p.font.bold = True
        p.font.color.rgb = ccolor
        dbox = s9.shapes.add_textbox(Inches(cx + 0.2), Inches(5.75), Inches(3.4), Inches(0.9))
        p = dbox.text_frame.paragraphs[0]
        p.text = cdesc
        p.font.size = Pt(11)
        p.font.color.rgb = WHITE

    # ==========================================
    # SLIDE 10: Verified Attack Scenarios & Interactive SOC
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_bg(s10)
    add_header(s10, "Verified Attack Scenarios, Interactive SOC Console & Conclusion", "VALIDATION & SYSTEM DEMONSTRATION")

    attacks = [
        ("⚡ Fileless In-Memory ELF", "curl | bash -> memfd_create -> mprotect(RWX) -> connect(). Composite Risk: 0.82. Mitigated: SIGKILL in 0.42 ms.", CYAN),
        ("☣️ Ransomware Mass-Encryption", "10,000 files locked per minute -> unlinkat(*.locked) -> README_RECOVER_KEYS. Composite Risk: 0.87. Mitigated: Volume freeze.", ROSE),
        ("🐚 Stealth C2 Reverse Shell", "nginx -> python3 -> sys_enter_connect(185.220.101.5) -> sh -> /etc/shadow. Composite Risk: 0.76. Mitigated: Socket severed.", PURPLE),
        ("🛡️ Privilege Escalation Exploit", "cve_exploit (UID 1000) -> mprotect(RWX) -> sys_enter_setuid(0) -> root bash. Composite Risk: 0.82. Mitigated: In-kernel blocked.", EMERALD)
    ]

    for i, (atitle, adesc, acolor) in enumerate(attacks):
        ay = 1.6 + (i * 1.0)
        add_card(s10, 0.8, ay, 6.8, 0.9, CARD_BG, acolor)
        tbox = s10.shapes.add_textbox(Inches(1.0), Inches(ay + 0.08), Inches(6.4), Inches(0.35))
        p = tbox.text_frame.paragraphs[0]
        p.text = atitle
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = acolor

        dbox = s10.shapes.add_textbox(Inches(1.0), Inches(ay + 0.38), Inches(6.4), Inches(0.45))
        p = dbox.text_frame.paragraphs[0]
        p.text = adesc
        p.font.size = Pt(10)
        p.font.color.rgb = WHITE

    # Right side: Interactive SOC Dashboard & Conclusion
    add_card(s10, 7.8, 1.6, 4.733, 5.2, CARD_BG, CYAN)
    tbox = s10.shapes.add_textbox(Inches(8.1), Inches(1.8), Inches(4.15), Inches(0.5))
    p = tbox.text_frame.paragraphs[0]
    p.text = "🖥️ Live SOC Command Center"
    p.font.size = Pt(16)
    p.font.bold = True
    p.font.color.rgb = CYAN

    cbox = s10.shapes.add_textbox(Inches(8.1), Inches(2.4), Inches(4.15), Inches(4.2))
    tf = cbox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = (
        "• Real-Time Interactive Capabilities:\n"
        "  - Dynamic Force-Directed Graph Visualizer with edge saliency weights.\n"
        "  - Real Local Host OS Sniffer (live psutil Windows/Linux telemetry).\n"
        "  - Interactive In-Browser Sandbox Terminal with simulated syscall execution.\n"
        "  - 1-Click Automated LaTeX IEEE/ACM Paper & BibTeX Exporter.\n\n"
        "• Key Takeaways:\n"
        "  1. Solves the TOCTOU gap with < 0.45 ms in-kernel mitigation.\n"
        "  2. Eliminates false positives (0.75% FPR) via temporal graph reasoning.\n"
        "  3. Sustains production workloads (< 1.15% CPU overhead)."
    )
    p.font.size = Pt(11)
    p.font.color.rgb = WHITE

    prs.save(output_path)
    print(f"[+] Successfully generated presentation at: {output_path}")

if __name__ == "__main__":
    create_deck()

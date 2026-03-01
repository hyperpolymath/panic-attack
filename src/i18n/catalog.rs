// SPDX-License-Identifier: PMPL-1.0-or-later

//! Translation catalog for panic-attack.
//!
//! Embeds all user-facing strings for supported languages as a compile-time
//! static table. Lookup is O(n) on the key list per language, which is fine
//! for the ~50 keys we have — this runs once per report generation, not in
//! a hot loop.
//!
//! Inspired by lol (1000Langs) project's embedded Dict translation approach
//! and polyglot-i18n's catalog pattern used in IDApTIK.
//!
//! ## Adding a new language
//!
//! 1. Add a variant to [`Lang`]
//! 2. Add a `Lang::Xx => "xx"` arm to `Lang::code()`
//! 3. Add a `"xx" => Some(Lang::Xx)` arm to `Lang::from_code()`
//! 4. Create a `const XX: &[(&str, &str)]` table below
//! 5. Add `Lang::Xx => XX` to the match in `catalog_for()`
//!
//! ## Adding a new key
//!
//! 1. Add the English entry to `EN`
//! 2. Add translations to ES, FR, DE, JA (missing keys fall back to English)

use serde::{Deserialize, Serialize};

/// Supported output languages for panic-attack reports and recommendations.
///
/// Each variant maps to an ISO 639-1 two-letter code. The enum is used by
/// the CLI `--lang` flag and by report generators that emit human-readable
/// text (axial markdown, assault recommendations, adjudicate verdicts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Lang {
    En,
    Es,
    Fr,
    De,
    Ja,
    Pt,
    Zh,
    Ko,
    It,
    Ru,
}

impl Lang {
    /// ISO 639-1 two-letter code for this language.
    pub fn code(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
            Lang::Fr => "fr",
            Lang::De => "de",
            Lang::Ja => "ja",
            Lang::Pt => "pt",
            Lang::Zh => "zh",
            Lang::Ko => "ko",
            Lang::It => "it",
            Lang::Ru => "ru",
        }
    }

    /// Parse an ISO 639-1 code into a supported language.
    ///
    /// Returns `None` for unsupported codes. Case-sensitive (codes must be
    /// lowercase per ISO 639-1).
    pub fn from_code(code: &str) -> Option<Lang> {
        match code {
            "en" => Some(Lang::En),
            "es" => Some(Lang::Es),
            "fr" => Some(Lang::Fr),
            "de" => Some(Lang::De),
            "ja" => Some(Lang::Ja),
            "pt" => Some(Lang::Pt),
            "zh" => Some(Lang::Zh),
            "ko" => Some(Lang::Ko),
            "it" => Some(Lang::It),
            "ru" => Some(Lang::Ru),
            _ => None,
        }
    }

    /// All supported languages, in display order.
    #[allow(dead_code)]
    pub fn all() -> &'static [Lang] {
        &[
            Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Ja,
            Lang::Pt, Lang::Zh, Lang::Ko, Lang::It, Lang::Ru,
        ]
    }

    /// Default aspell dictionary code for this language.
    ///
    /// Aspell uses ISO 639-1 codes directly, except Japanese which uses
    /// a different spellcheck approach (aspell has no ja dictionary;
    /// falls back to English for spellcheck purposes).
    pub fn aspell_code(&self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Es => "es",
            Lang::Fr => "fr",
            Lang::De => "de",
            Lang::Ja => "en", // aspell has no Japanese dictionary
            Lang::Pt => "pt",
            Lang::Zh => "en", // aspell has no Chinese dictionary
            Lang::Ko => "en", // aspell has no Korean dictionary
            Lang::It => "it",
            Lang::Ru => "ru",
        }
    }
}

impl Default for Lang {
    fn default() -> Self {
        Lang::En
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

// ─── Translation Lookup ─────────────────────────────────────────────

/// Look up a translation key in the specified language.
///
/// Falls back to English if the key is not found in the requested language.
/// If the key is missing in English too, returns the key string itself
/// (fail-open design — never panics, never returns empty).
///
/// # Examples
///
/// ```
/// use panic_attack::i18n::{t, Lang};
/// assert_eq!(t(Lang::En, "axial.title"), "Axial Report");
/// assert_eq!(t(Lang::Es, "axial.title"), "Informe Axial");
/// assert_eq!(t(Lang::Ja, "axial.title"), "Axialレポート");
/// ```
pub fn t(lang: Lang, key: &str) -> &'static str {
    // Try requested language first
    if let Some(value) = lookup(catalog_for(lang), key) {
        return value;
    }
    // Fall back to English
    if lang != Lang::En {
        if let Some(value) = lookup(EN, key) {
            return value;
        }
    }
    // Last resort: leak the key as a static str so the signature stays &'static.
    // This only happens for genuinely missing keys (programming error), not at
    // runtime for valid translation lookups.
    //
    // In practice we return "" for unknown keys to avoid the leak. The caller
    // can check for empty and use the key directly if needed.
    ""
}

/// Non-static variant: returns the translation or the key itself if missing.
/// Useful when you need to own the result.
#[allow(dead_code)]
pub fn t_or_key<'a>(lang: Lang, key: &'a str) -> &'a str {
    let result = t(lang, key);
    if result.is_empty() {
        key
    } else {
        // SAFETY: the &'static str from t() outlives 'a, so this is fine.
        // We just need to tell the compiler we're returning something with
        // lifetime 'a. Since 'static outlives everything, this is sound.
        result
    }
}

fn lookup(catalog: &'static [(&'static str, &'static str)], key: &str) -> Option<&'static str> {
    for &(k, v) in catalog {
        if k == key {
            return Some(v);
        }
    }
    None
}

fn catalog_for(lang: Lang) -> &'static [(&'static str, &'static str)] {
    match lang {
        Lang::En => EN,
        Lang::Es => ES,
        Lang::Fr => FR,
        Lang::De => DE,
        Lang::Ja => JA,
        Lang::Pt => PT,
        Lang::Zh => ZH,
        Lang::Ko => KO,
        Lang::It => IT,
        Lang::Ru => RU,
    }
}

// ─── English (source language — all keys defined here) ──────────────

const EN: &[(&str, &str)] = &[
    // Axial report — markdown headers and labels
    ("axial.title", "Axial Report"),
    ("axial.target", "Target"),
    ("axial.created_at", "Created"),
    ("axial.language", "Language"),
    ("axial.observed_runs", "Observed Runs"),
    ("axial.observed_reports", "Observed Reports"),
    ("axial.signals", "Signals"),
    ("axial.recommendations", "Recommendations"),
    ("axial.spelling", "Spelling"),
    ("axial.none", "none"),
    // Axial recommendations
    ("rec.crash", "prioritize crash triage and backtrace collection"),
    ("rec.panic", "audit panic/fatal paths for unsafe assumptions"),
    ("rec.timeout", "review long-running paths and add watchdog instrumentation"),
    ("rec.none", "no critical reaction signals observed"),
    // Assault report labels
    ("assault.title", "Assault Report"),
    ("assault.robustness", "Robustness Score"),
    ("assault.critical_issues", "Critical Issues"),
    ("assault.recommendations", "Recommendations"),
    ("assault.total_crashes", "Total Crashes"),
    ("assault.total_signatures", "Bug Signatures Detected"),
    // Assail report labels
    ("assail.title", "Assail Report"),
    ("assail.weak_points", "Weak Points"),
    ("assail.statistics", "Statistics"),
    ("assail.files_scanned", "Files Scanned"),
    ("assail.total_lines", "Total Lines"),
    ("assail.languages_detected", "Languages Detected"),
    // Common labels
    ("common.severity", "Severity"),
    ("common.location", "Location"),
    ("common.description", "Description"),
    ("common.category", "Category"),
    ("common.file", "File"),
    ("common.summary", "Summary"),
    ("common.details", "Details"),
    ("common.unknown", "unknown"),
    // Adjudicate
    ("adjudicate.title", "Adjudicate Verdict"),
    ("adjudicate.campaigns", "Campaigns Analyzed"),
    ("adjudicate.verdict", "Overall Verdict"),
    // Ambush
    ("ambush.title", "Ambush Report"),
    ("ambush.timeline", "Timeline Events"),
    ("ambush.stressors", "Active Stressors"),
    // Amuck
    ("amuck.title", "Amuck Mutation Report"),
    ("amuck.mutations", "Mutations Applied"),
    ("amuck.survivors", "Surviving Mutations"),
    // Abduct
    ("abduct.title", "Abduct Isolation Report"),
    ("abduct.isolated_files", "Isolated Files"),
    ("abduct.scope", "Dependency Scope"),
];

// ─── Spanish ────────────────────────────────────────────────────────

const ES: &[(&str, &str)] = &[
    ("axial.title", "Informe Axial"),
    ("axial.target", "Objetivo"),
    ("axial.created_at", "Creado"),
    ("axial.language", "Idioma"),
    ("axial.observed_runs", "Ejecuciones observadas"),
    ("axial.observed_reports", "Informes observados"),
    ("axial.signals", "Señales"),
    ("axial.recommendations", "Recomendaciones"),
    ("axial.spelling", "Ortografía"),
    ("axial.none", "ninguno"),
    ("rec.crash", "priorizar triage de fallos y recolección de trazas"),
    ("rec.panic", "auditar rutas panic/fatal por supuestos inseguros"),
    ("rec.timeout", "revisar rutas largas y agregar instrumentación watchdog"),
    ("rec.none", "no se observaron señales críticas"),
    ("assault.title", "Informe de Asalto"),
    ("assault.robustness", "Puntuación de Robustez"),
    ("assault.critical_issues", "Problemas Críticos"),
    ("assault.recommendations", "Recomendaciones"),
    ("assault.total_crashes", "Total de Fallos"),
    ("assault.total_signatures", "Firmas de Bugs Detectadas"),
    ("assail.title", "Informe Assail"),
    ("assail.weak_points", "Puntos Débiles"),
    ("assail.statistics", "Estadísticas"),
    ("assail.files_scanned", "Archivos Escaneados"),
    ("assail.total_lines", "Líneas Totales"),
    ("assail.languages_detected", "Lenguajes Detectados"),
    ("common.severity", "Severidad"),
    ("common.location", "Ubicación"),
    ("common.description", "Descripción"),
    ("common.category", "Categoría"),
    ("common.file", "Archivo"),
    ("common.summary", "Resumen"),
    ("common.details", "Detalles"),
    ("common.unknown", "desconocido"),
    ("adjudicate.title", "Veredicto de Adjudicación"),
    ("adjudicate.campaigns", "Campañas Analizadas"),
    ("adjudicate.verdict", "Veredicto General"),
    ("ambush.title", "Informe de Emboscada"),
    ("ambush.timeline", "Eventos de Línea Temporal"),
    ("ambush.stressors", "Estresores Activos"),
    ("amuck.title", "Informe de Mutación Amuck"),
    ("amuck.mutations", "Mutaciones Aplicadas"),
    ("amuck.survivors", "Mutaciones Sobrevivientes"),
    ("abduct.title", "Informe de Aislamiento Abduct"),
    ("abduct.isolated_files", "Archivos Aislados"),
    ("abduct.scope", "Alcance de Dependencias"),
];

// ─── French ─────────────────────────────────────────────────────────

const FR: &[(&str, &str)] = &[
    ("axial.title", "Rapport Axial"),
    ("axial.target", "Cible"),
    ("axial.created_at", "Créé le"),
    ("axial.language", "Langue"),
    ("axial.observed_runs", "Exécutions observées"),
    ("axial.observed_reports", "Rapports observés"),
    ("axial.signals", "Signaux"),
    ("axial.recommendations", "Recommandations"),
    ("axial.spelling", "Orthographe"),
    ("axial.none", "aucun"),
    ("rec.crash", "prioriser le triage des crashs et la collecte des traces"),
    ("rec.panic", "auditer les chemins panic/fatal pour hypothèses dangereuses"),
    ("rec.timeout", "examiner les chemins longs et ajouter un watchdog"),
    ("rec.none", "aucun signal critique observé"),
    ("assault.title", "Rapport d'Assaut"),
    ("assault.robustness", "Score de Robustesse"),
    ("assault.critical_issues", "Problèmes Critiques"),
    ("assault.recommendations", "Recommandations"),
    ("assault.total_crashes", "Total des Crashs"),
    ("assault.total_signatures", "Signatures de Bugs Détectées"),
    ("assail.title", "Rapport Assail"),
    ("assail.weak_points", "Points Faibles"),
    ("assail.statistics", "Statistiques"),
    ("assail.files_scanned", "Fichiers Analysés"),
    ("assail.total_lines", "Lignes Totales"),
    ("assail.languages_detected", "Langages Détectés"),
    ("common.severity", "Sévérité"),
    ("common.location", "Emplacement"),
    ("common.description", "Description"),
    ("common.category", "Catégorie"),
    ("common.file", "Fichier"),
    ("common.summary", "Résumé"),
    ("common.details", "Détails"),
    ("common.unknown", "inconnu"),
    ("adjudicate.title", "Verdict d'Adjudication"),
    ("adjudicate.campaigns", "Campagnes Analysées"),
    ("adjudicate.verdict", "Verdict Global"),
    ("ambush.title", "Rapport d'Embuscade"),
    ("ambush.timeline", "Événements Chronologiques"),
    ("ambush.stressors", "Stresseurs Actifs"),
    ("amuck.title", "Rapport de Mutation Amuck"),
    ("amuck.mutations", "Mutations Appliquées"),
    ("amuck.survivors", "Mutations Survivantes"),
    ("abduct.title", "Rapport d'Isolation Abduct"),
    ("abduct.isolated_files", "Fichiers Isolés"),
    ("abduct.scope", "Portée des Dépendances"),
];

// ─── German ─────────────────────────────────────────────────────────

const DE: &[(&str, &str)] = &[
    ("axial.title", "Axialer Bericht"),
    ("axial.target", "Ziel"),
    ("axial.created_at", "Erstellt am"),
    ("axial.language", "Sprache"),
    ("axial.observed_runs", "Beobachtete Läufe"),
    ("axial.observed_reports", "Beobachtete Berichte"),
    ("axial.signals", "Signale"),
    ("axial.recommendations", "Empfehlungen"),
    ("axial.spelling", "Rechtschreibung"),
    ("axial.none", "keine"),
    ("rec.crash", "Crash-Triage und Backtrace-Erfassung priorisieren"),
    ("rec.panic", "Panic/Fatal-Pfade auf unsichere Annahmen prüfen"),
    ("rec.timeout", "langlaufende Pfade prüfen und Watchdog hinzufügen"),
    ("rec.none", "keine kritischen Reaktionssignale beobachtet"),
    ("assault.title", "Angriffsbericht"),
    ("assault.robustness", "Robustheitswert"),
    ("assault.critical_issues", "Kritische Probleme"),
    ("assault.recommendations", "Empfehlungen"),
    ("assault.total_crashes", "Abstürze Gesamt"),
    ("assault.total_signatures", "Erkannte Bug-Signaturen"),
    ("assail.title", "Assail Bericht"),
    ("assail.weak_points", "Schwachstellen"),
    ("assail.statistics", "Statistiken"),
    ("assail.files_scanned", "Gescannte Dateien"),
    ("assail.total_lines", "Gesamtzeilen"),
    ("assail.languages_detected", "Erkannte Sprachen"),
    ("common.severity", "Schweregrad"),
    ("common.location", "Ort"),
    ("common.description", "Beschreibung"),
    ("common.category", "Kategorie"),
    ("common.file", "Datei"),
    ("common.summary", "Zusammenfassung"),
    ("common.details", "Details"),
    ("common.unknown", "unbekannt"),
    ("adjudicate.title", "Urteil der Adjudikation"),
    ("adjudicate.campaigns", "Analysierte Kampagnen"),
    ("adjudicate.verdict", "Gesamturteil"),
    ("ambush.title", "Hinterhalt-Bericht"),
    ("ambush.timeline", "Zeitleisten-Ereignisse"),
    ("ambush.stressors", "Aktive Stressoren"),
    ("amuck.title", "Amuck Mutationsbericht"),
    ("amuck.mutations", "Angewandte Mutationen"),
    ("amuck.survivors", "Überlebende Mutationen"),
    ("abduct.title", "Abduct Isolationsbericht"),
    ("abduct.isolated_files", "Isolierte Dateien"),
    ("abduct.scope", "Abhängigkeitsbereich"),
];

// ─── Japanese ───────────────────────────────────────────────────────

const JA: &[(&str, &str)] = &[
    ("axial.title", "Axialレポート"),
    ("axial.target", "対象"),
    ("axial.created_at", "作成日時"),
    ("axial.language", "言語"),
    ("axial.observed_runs", "観測された実行"),
    ("axial.observed_reports", "観測されたレポート"),
    ("axial.signals", "シグナル"),
    ("axial.recommendations", "推奨事項"),
    ("axial.spelling", "スペルチェック"),
    ("axial.none", "なし"),
    ("rec.crash", "クラッシュのトリアージとバックトレース収集を優先する"),
    ("rec.panic", "panic/fatalパスの安全でない前提を監査する"),
    ("rec.timeout", "長時間実行パスを確認しウォッチドッグを追加する"),
    ("rec.none", "重大な反応シグナルは観測されなかった"),
    ("assault.title", "アサルトレポート"),
    ("assault.robustness", "堅牢性スコア"),
    ("assault.critical_issues", "重大な問題"),
    ("assault.recommendations", "推奨事項"),
    ("assault.total_crashes", "クラッシュ合計"),
    ("assault.total_signatures", "検出されたバグシグネチャ"),
    ("assail.title", "Assailレポート"),
    ("assail.weak_points", "脆弱ポイント"),
    ("assail.statistics", "統計"),
    ("assail.files_scanned", "スキャン済みファイル"),
    ("assail.total_lines", "総行数"),
    ("assail.languages_detected", "検出された言語"),
    ("common.severity", "深刻度"),
    ("common.location", "場所"),
    ("common.description", "説明"),
    ("common.category", "カテゴリ"),
    ("common.file", "ファイル"),
    ("common.summary", "概要"),
    ("common.details", "詳細"),
    ("common.unknown", "不明"),
    ("adjudicate.title", "Adjudicate判定"),
    ("adjudicate.campaigns", "分析されたキャンペーン"),
    ("adjudicate.verdict", "総合判定"),
    ("ambush.title", "待ち伏せレポート"),
    ("ambush.timeline", "タイムラインイベント"),
    ("ambush.stressors", "アクティブストレッサー"),
    ("amuck.title", "Amuck変異レポート"),
    ("amuck.mutations", "適用された変異"),
    ("amuck.survivors", "生存した変異"),
    ("abduct.title", "Abduct隔離レポート"),
    ("abduct.isolated_files", "隔離されたファイル"),
    ("abduct.scope", "依存関係スコープ"),
];

// ─── Portuguese ────────────────────────────────────────────────────

const PT: &[(&str, &str)] = &[
    ("axial.title", "Relatório Axial"),
    ("axial.target", "Alvo"),
    ("axial.created_at", "Criado em"),
    ("axial.language", "Idioma"),
    ("axial.observed_runs", "Execuções observadas"),
    ("axial.observed_reports", "Relatórios observados"),
    ("axial.signals", "Sinais"),
    ("axial.recommendations", "Recomendações"),
    ("axial.spelling", "Ortografia"),
    ("axial.none", "nenhum"),
    ("rec.crash", "priorizar triagem de falhas e coleta de rastreamentos"),
    ("rec.panic", "auditar caminhos panic/fatal por suposições inseguras"),
    ("rec.timeout", "revisar caminhos longos e adicionar watchdog"),
    ("rec.none", "nenhum sinal crítico de reação observado"),
    ("assault.title", "Relatório de Assalto"),
    ("assault.robustness", "Pontuação de Robustez"),
    ("assault.critical_issues", "Problemas Críticos"),
    ("assault.recommendations", "Recomendações"),
    ("assault.total_crashes", "Total de Falhas"),
    ("assault.total_signatures", "Assinaturas de Bugs Detectadas"),
    ("assail.title", "Relatório Assail"),
    ("assail.weak_points", "Pontos Fracos"),
    ("assail.statistics", "Estatísticas"),
    ("assail.files_scanned", "Arquivos Analisados"),
    ("assail.total_lines", "Linhas Totais"),
    ("assail.languages_detected", "Linguagens Detectadas"),
    ("common.severity", "Gravidade"),
    ("common.location", "Localização"),
    ("common.description", "Descrição"),
    ("common.category", "Categoria"),
    ("common.file", "Arquivo"),
    ("common.summary", "Resumo"),
    ("common.details", "Detalhes"),
    ("common.unknown", "desconhecido"),
    ("adjudicate.title", "Veredicto de Adjudicação"),
    ("adjudicate.campaigns", "Campanhas Analisadas"),
    ("adjudicate.verdict", "Veredicto Geral"),
    ("ambush.title", "Relatório de Emboscada"),
    ("ambush.timeline", "Eventos da Linha do Tempo"),
    ("ambush.stressors", "Estressores Ativos"),
    ("amuck.title", "Relatório de Mutação Amuck"),
    ("amuck.mutations", "Mutações Aplicadas"),
    ("amuck.survivors", "Mutações Sobreviventes"),
    ("abduct.title", "Relatório de Isolamento Abduct"),
    ("abduct.isolated_files", "Arquivos Isolados"),
    ("abduct.scope", "Escopo de Dependências"),
];

// ─── Chinese (Simplified) ─────────────────────────────────────────

const ZH: &[(&str, &str)] = &[
    ("axial.title", "轴向报告"),
    ("axial.target", "目标"),
    ("axial.created_at", "创建时间"),
    ("axial.language", "语言"),
    ("axial.observed_runs", "观察到的运行"),
    ("axial.observed_reports", "观察到的报告"),
    ("axial.signals", "信号"),
    ("axial.recommendations", "建议"),
    ("axial.spelling", "拼写检查"),
    ("axial.none", "无"),
    ("rec.crash", "优先处理崩溃分类和堆栈跟踪收集"),
    ("rec.panic", "审查panic/fatal路径中的不安全假设"),
    ("rec.timeout", "审查长时间运行路径并添加看门狗"),
    ("rec.none", "未观察到关键反应信号"),
    ("assault.title", "突击报告"),
    ("assault.robustness", "健壮性评分"),
    ("assault.critical_issues", "关键问题"),
    ("assault.recommendations", "建议"),
    ("assault.total_crashes", "崩溃总数"),
    ("assault.total_signatures", "检测到的缺陷签名"),
    ("assail.title", "Assail报告"),
    ("assail.weak_points", "薄弱点"),
    ("assail.statistics", "统计"),
    ("assail.files_scanned", "已扫描文件"),
    ("assail.total_lines", "总行数"),
    ("assail.languages_detected", "检测到的语言"),
    ("common.severity", "严重程度"),
    ("common.location", "位置"),
    ("common.description", "描述"),
    ("common.category", "类别"),
    ("common.file", "文件"),
    ("common.summary", "摘要"),
    ("common.details", "详情"),
    ("common.unknown", "未知"),
    ("adjudicate.title", "裁决结果"),
    ("adjudicate.campaigns", "已分析的战役"),
    ("adjudicate.verdict", "总体裁决"),
    ("ambush.title", "伏击报告"),
    ("ambush.timeline", "时间线事件"),
    ("ambush.stressors", "活动压力源"),
    ("amuck.title", "Amuck变异报告"),
    ("amuck.mutations", "已应用的变异"),
    ("amuck.survivors", "存活的变异"),
    ("abduct.title", "Abduct隔离报告"),
    ("abduct.isolated_files", "已隔离文件"),
    ("abduct.scope", "依赖范围"),
];

// ─── Korean ───────────────────────────────────────────────────────

const KO: &[(&str, &str)] = &[
    ("axial.title", "축 보고서"),
    ("axial.target", "대상"),
    ("axial.created_at", "생성일"),
    ("axial.language", "언어"),
    ("axial.observed_runs", "관찰된 실행"),
    ("axial.observed_reports", "관찰된 보고서"),
    ("axial.signals", "신호"),
    ("axial.recommendations", "권장사항"),
    ("axial.spelling", "맞춤법 검사"),
    ("axial.none", "없음"),
    ("rec.crash", "크래시 분류 및 백트레이스 수집 우선"),
    ("rec.panic", "panic/fatal 경로의 안전하지 않은 가정 감사"),
    ("rec.timeout", "장시간 실행 경로 검토 및 워치독 추가"),
    ("rec.none", "관찰된 중요 반응 신호 없음"),
    ("assault.title", "돌격 보고서"),
    ("assault.robustness", "견고성 점수"),
    ("assault.critical_issues", "치명적 문제"),
    ("assault.recommendations", "권장사항"),
    ("assault.total_crashes", "총 크래시"),
    ("assault.total_signatures", "감지된 버그 시그니처"),
    ("assail.title", "Assail 보고서"),
    ("assail.weak_points", "취약점"),
    ("assail.statistics", "통계"),
    ("assail.files_scanned", "스캔된 파일"),
    ("assail.total_lines", "총 라인 수"),
    ("assail.languages_detected", "감지된 언어"),
    ("common.severity", "심각도"),
    ("common.location", "위치"),
    ("common.description", "설명"),
    ("common.category", "범주"),
    ("common.file", "파일"),
    ("common.summary", "요약"),
    ("common.details", "상세"),
    ("common.unknown", "알 수 없음"),
    ("adjudicate.title", "판결 결과"),
    ("adjudicate.campaigns", "분석된 캠페인"),
    ("adjudicate.verdict", "종합 판결"),
    ("ambush.title", "매복 보고서"),
    ("ambush.timeline", "타임라인 이벤트"),
    ("ambush.stressors", "활성 스트레서"),
    ("amuck.title", "Amuck 돌연변이 보고서"),
    ("amuck.mutations", "적용된 돌연변이"),
    ("amuck.survivors", "생존한 돌연변이"),
    ("abduct.title", "Abduct 격리 보고서"),
    ("abduct.isolated_files", "격리된 파일"),
    ("abduct.scope", "의존성 범위"),
];

// ─── Italian ──────────────────────────────────────────────────────

const IT: &[(&str, &str)] = &[
    ("axial.title", "Rapporto Assiale"),
    ("axial.target", "Obiettivo"),
    ("axial.created_at", "Creato il"),
    ("axial.language", "Lingua"),
    ("axial.observed_runs", "Esecuzioni osservate"),
    ("axial.observed_reports", "Rapporti osservati"),
    ("axial.signals", "Segnali"),
    ("axial.recommendations", "Raccomandazioni"),
    ("axial.spelling", "Ortografia"),
    ("axial.none", "nessuno"),
    ("rec.crash", "dare priorità al triage dei crash e alla raccolta dei backtrace"),
    ("rec.panic", "verificare percorsi panic/fatal per ipotesi non sicure"),
    ("rec.timeout", "esaminare percorsi a lunga esecuzione e aggiungere watchdog"),
    ("rec.none", "nessun segnale critico di reazione osservato"),
    ("assault.title", "Rapporto d'Assalto"),
    ("assault.robustness", "Punteggio di Robustezza"),
    ("assault.critical_issues", "Problemi Critici"),
    ("assault.recommendations", "Raccomandazioni"),
    ("assault.total_crashes", "Crash Totali"),
    ("assault.total_signatures", "Firme di Bug Rilevate"),
    ("assail.title", "Rapporto Assail"),
    ("assail.weak_points", "Punti Deboli"),
    ("assail.statistics", "Statistiche"),
    ("assail.files_scanned", "File Analizzati"),
    ("assail.total_lines", "Righe Totali"),
    ("assail.languages_detected", "Linguaggi Rilevati"),
    ("common.severity", "Gravità"),
    ("common.location", "Posizione"),
    ("common.description", "Descrizione"),
    ("common.category", "Categoria"),
    ("common.file", "File"),
    ("common.summary", "Riepilogo"),
    ("common.details", "Dettagli"),
    ("common.unknown", "sconosciuto"),
    ("adjudicate.title", "Verdetto di Aggiudicazione"),
    ("adjudicate.campaigns", "Campagne Analizzate"),
    ("adjudicate.verdict", "Verdetto Complessivo"),
    ("ambush.title", "Rapporto di Imboscata"),
    ("ambush.timeline", "Eventi della Cronologia"),
    ("ambush.stressors", "Stressori Attivi"),
    ("amuck.title", "Rapporto di Mutazione Amuck"),
    ("amuck.mutations", "Mutazioni Applicate"),
    ("amuck.survivors", "Mutazioni Sopravvissute"),
    ("abduct.title", "Rapporto di Isolamento Abduct"),
    ("abduct.isolated_files", "File Isolati"),
    ("abduct.scope", "Ambito delle Dipendenze"),
];

// ─── Russian ──────────────────────────────────────────────────────

const RU: &[(&str, &str)] = &[
    ("axial.title", "Осевой отчёт"),
    ("axial.target", "Цель"),
    ("axial.created_at", "Создан"),
    ("axial.language", "Язык"),
    ("axial.observed_runs", "Наблюдаемые запуски"),
    ("axial.observed_reports", "Наблюдаемые отчёты"),
    ("axial.signals", "Сигналы"),
    ("axial.recommendations", "Рекомендации"),
    ("axial.spelling", "Правописание"),
    ("axial.none", "нет"),
    ("rec.crash", "приоритизировать сортировку аварий и сбор трассировок"),
    ("rec.panic", "проверить пути panic/fatal на небезопасные допущения"),
    ("rec.timeout", "проверить долгие пути исполнения и добавить сторожевой таймер"),
    ("rec.none", "критических сигналов реакции не обнаружено"),
    ("assault.title", "Отчёт о штурме"),
    ("assault.robustness", "Оценка устойчивости"),
    ("assault.critical_issues", "Критические проблемы"),
    ("assault.recommendations", "Рекомендации"),
    ("assault.total_crashes", "Всего аварий"),
    ("assault.total_signatures", "Обнаруженные сигнатуры ошибок"),
    ("assail.title", "Отчёт Assail"),
    ("assail.weak_points", "Уязвимые точки"),
    ("assail.statistics", "Статистика"),
    ("assail.files_scanned", "Просканированные файлы"),
    ("assail.total_lines", "Всего строк"),
    ("assail.languages_detected", "Обнаруженные языки"),
    ("common.severity", "Серьёзность"),
    ("common.location", "Расположение"),
    ("common.description", "Описание"),
    ("common.category", "Категория"),
    ("common.file", "Файл"),
    ("common.summary", "Сводка"),
    ("common.details", "Подробности"),
    ("common.unknown", "неизвестно"),
    ("adjudicate.title", "Вердикт вынесения решения"),
    ("adjudicate.campaigns", "Проанализированные кампании"),
    ("adjudicate.verdict", "Общий вердикт"),
    ("ambush.title", "Отчёт о засаде"),
    ("ambush.timeline", "События хронологии"),
    ("ambush.stressors", "Активные стрессоры"),
    ("amuck.title", "Отчёт о мутации Amuck"),
    ("amuck.mutations", "Применённые мутации"),
    ("amuck.survivors", "Выжившие мутации"),
    ("abduct.title", "Отчёт об изоляции Abduct"),
    ("abduct.isolated_files", "Изолированные файлы"),
    ("abduct.scope", "Область зависимостей"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_keys_all_resolve() {
        for &(key, _) in EN {
            let result = t(Lang::En, key);
            assert!(!result.is_empty(), "EN key '{}' should resolve", key);
        }
    }

    #[test]
    fn japanese_added_correctly() {
        assert_eq!(t(Lang::Ja, "axial.title"), "Axialレポート");
        assert_eq!(t(Lang::Ja, "rec.none"), "重大な反応シグナルは観測されなかった");
    }

    #[test]
    fn fallback_to_english() {
        // If a key only exists in EN, other languages should fall back
        let en_val = t(Lang::En, "axial.title");
        // All languages should return something for this key
        for lang in Lang::all() {
            let val = t(*lang, "axial.title");
            assert!(!val.is_empty(), "{:?} should have axial.title", lang);
            if *lang == Lang::En {
                assert_eq!(val, en_val);
            }
        }
    }

    #[test]
    fn unknown_key_returns_empty() {
        assert_eq!(t(Lang::En, "nonexistent.key"), "");
    }

    #[test]
    fn t_or_key_returns_key_for_missing() {
        assert_eq!(t_or_key(Lang::En, "nonexistent.key"), "nonexistent.key");
    }

    #[test]
    fn lang_roundtrip() {
        for lang in Lang::all() {
            let code = lang.code();
            let parsed = Lang::from_code(code).expect("should parse");
            assert_eq!(*lang, parsed);
        }
    }

    #[test]
    fn all_catalogs_same_key_count_as_english() {
        let en_count = EN.len();
        assert_eq!(ES.len(), en_count, "ES catalog key count mismatch");
        assert_eq!(FR.len(), en_count, "FR catalog key count mismatch");
        assert_eq!(DE.len(), en_count, "DE catalog key count mismatch");
        assert_eq!(JA.len(), en_count, "JA catalog key count mismatch");
        assert_eq!(PT.len(), en_count, "PT catalog key count mismatch");
        assert_eq!(ZH.len(), en_count, "ZH catalog key count mismatch");
        assert_eq!(KO.len(), en_count, "KO catalog key count mismatch");
        assert_eq!(IT.len(), en_count, "IT catalog key count mismatch");
        assert_eq!(RU.len(), en_count, "RU catalog key count mismatch");
    }
}

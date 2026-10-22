//! Pure-Rust port of vendored uchardet (cchardet 2.2.0a2 / Mozilla universalchardet).

use crate::uchardet_data::*;

const E_START: usize = 0;
const E_ITS_ME: usize = 2;
const SHORTCUT_THRESHOLD: f32 = 0.95;
const MINIMUM_THRESHOLD: f32 = 0.20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbingState {
    Detecting,
    FoundIt,
    NotMe,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputState {
    PureAscii,
    EscAscii,
    Highbyte,
}

struct CodingStateMachine {
    current_state: usize,
    current_char_len: usize,
    model: &'static SmModel,
}

impl CodingStateMachine {
    fn new(model: &'static SmModel) -> Self {
        Self { current_state: E_START, current_char_len: 0, model }
    }

    fn next_state(&mut self, c: u8) -> usize {
        let byte_cls = self.model.class_table[c as usize] as usize;
        if self.current_state == E_START {
            self.current_char_len = self.model.char_len_table[byte_cls] as usize;
        }
        self.current_state = self.model.state_table[self.current_state * self.model.class_factor + byte_cls] as usize;
        self.current_state
    }
}

fn filter_without_english_letters(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut meet_msb = false;
    let mut prev = 0;
    for (cur, &b) in buf.iter().enumerate() {
        if b & 0x80 != 0 {
            meet_msb = true;
        } else if !b.is_ascii_alphabetic() {
            if meet_msb && cur > prev {
                out.extend_from_slice(&buf[prev..cur]);
                prev = cur + 1;
                out.push(b' ');
                meet_msb = false;
            } else {
                prev = cur + 1;
            }
        }
    }
    if meet_msb && buf.len() > prev {
        out.extend_from_slice(&buf[prev..]);
    }
    out
}

fn filter_with_english_letters(buf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut is_in_tag = false;
    let mut prev = 0;
    for (cur, &b) in buf.iter().enumerate() {
        if b == b'>' {
            is_in_tag = false;
        } else if b == b'<' {
            is_in_tag = true;
        }
        if b & 0x80 == 0 && !b.is_ascii_alphabetic() {
            if cur > prev && !is_in_tag {
                out.extend_from_slice(&buf[prev..cur]);
                prev = cur + 1;
                out.push(b' ');
            } else {
                prev = cur + 1;
            }
        }
    }
    if !is_in_tag {
        out.extend_from_slice(&buf[prev..]);
    }
    out
}

struct EscCharSetProber {
    coding_sm: [CodingStateMachine; 4],
    state: ProbingState,
    detected_charset: &'static str,
}

impl EscCharSetProber {
    fn new() -> Self {
        Self {
            coding_sm: [
                CodingStateMachine::new(&HZSMMODEL),
                CodingStateMachine::new(&ISO2022CNSMMODEL),
                CodingStateMachine::new(&ISO2022JPSMMODEL),
                CodingStateMachine::new(&ISO2022KRSMMODEL),
            ],
            state: ProbingState::Detecting,
            detected_charset: "",
        }
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        for &b in buf {
            if self.state != ProbingState::Detecting {
                break;
            }
            for j in (0..4).rev() {
                if self.coding_sm[j].next_state(b) == E_ITS_ME {
                    self.state = ProbingState::FoundIt;
                    self.detected_charset = self.coding_sm[j].model.name;
                    return self.state;
                }
            }
        }
        self.state
    }
}

struct Utf8Prober {
    coding_sm: CodingStateMachine,
    state: ProbingState,
    num_of_mb_char: u32,
}

impl Utf8Prober {
    fn new() -> Self {
        Self { coding_sm: CodingStateMachine::new(&UTF8SMMODEL), state: ProbingState::Detecting, num_of_mb_char: 0 }
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        for &b in buf {
            let coding_state = self.coding_sm.next_state(b);
            if coding_state == E_ITS_ME {
                self.state = ProbingState::FoundIt;
                break;
            }
            if coding_state == E_START && self.coding_sm.current_char_len >= 2 {
                self.num_of_mb_char += 1;
            }
        }
        if self.state == ProbingState::Detecting && self.get_confidence() > SHORTCUT_THRESHOLD {
            self.state = ProbingState::FoundIt;
        }
        self.state
    }

    fn get_confidence(&self) -> f32 {
        let mut unlike: f32 = 0.99;
        if self.num_of_mb_char < 6 {
            for _ in 0..self.num_of_mb_char {
                unlike *= 0.50_f32;
            }
            1.0_f32 - unlike
        } else {
            0.99_f32
        }
    }
}

struct CharDistributionAnalysis {
    freq_chars: u32,
    total_chars: u32,
    char_to_freq_order: &'static [i16],
    typical_distribution_ratio: f32,
    get_order: fn(u8, u8) -> i32,
}

impl CharDistributionAnalysis {
    fn new(char_to_freq_order: &'static [i16], typical_distribution_ratio: f32, get_order: fn(u8, u8) -> i32) -> Self {
        Self { freq_chars: 0, total_chars: 0, char_to_freq_order, typical_distribution_ratio, get_order }
    }

    fn handle_one_char(&mut self, b0: u8, b1: u8, char_len: usize) {
        let order = if char_len == 2 { (self.get_order)(b0, b1) } else { -1 };
        if order >= 0 {
            self.total_chars += 1;
            if (order as usize) < self.char_to_freq_order.len() && 512 > self.char_to_freq_order[order as usize] {
                self.freq_chars += 1;
            }
        }
    }

    fn get_confidence(&self) -> f32 {
        if self.total_chars == 0 || self.freq_chars <= 4 {
            return 0.01_f32;
        }
        if self.total_chars != self.freq_chars {
            let r = (self.freq_chars as f32)
                / (((self.total_chars - self.freq_chars) as f32) * self.typical_distribution_ratio);
            if r < 0.99_f32 {
                return r;
            }
        }
        0.99_f32
    }

    fn got_enough_data(&self) -> bool {
        self.total_chars > 1024
    }
}

struct JapaneseContextAnalysis {
    rel_sample: [u32; 6],
    total_rel: u32,
    last_char_order: i32,
    done: bool,
    get_order: fn(u8, u8) -> i32,
}

impl JapaneseContextAnalysis {
    fn new(get_order: fn(u8, u8) -> i32) -> Self {
        Self { rel_sample: [0; 6], total_rel: 0, last_char_order: -1, done: false, get_order }
    }

    fn handle_one_char(&mut self, b0: u8, b1: u8, char_len: usize) {
        if self.total_rel > 1000 {
            self.done = true;
        }
        if self.done {
            return;
        }
        let order = if char_len == 2 { (self.get_order)(b0, b1) } else { -1 };
        if order != -1 && self.last_char_order != -1 {
            self.total_rel += 1;
            self.rel_sample[JP2_CHAR_CONTEXT[self.last_char_order as usize][order as usize] as usize] += 1;
        }
        self.last_char_order = order;
    }

    fn get_confidence(&self) -> f32 {
        if self.total_rel > 4 {
            ((self.total_rel - self.rel_sample[0]) as f32) / (self.total_rel as f32)
        } else {
            -1.0_f32
        }
    }

    fn got_enough_data(&self) -> bool {
        self.total_rel > 100
    }
}

fn sjis_order(b0: u8, b1: u8) -> i32 {
    let mut order = if (0x81..=0x9f).contains(&b0) {
        188 * (b0 as i32 - 0x81)
    } else if (0xe0..=0xef).contains(&b0) {
        188 * (b0 as i32 - 0xe0 + 31)
    } else {
        return -1;
    };
    order += b1 as i32 - 0x40;
    if b1 > 0x7f {
        order -= 1;
    }
    order
}

fn eucjp_order(b0: u8, b1: u8) -> i32 {
    if b0 >= 0xa0 { 94 * (b0 as i32 - 0xa1) + b1 as i32 - 0xa1 } else { -1 }
}

fn gb2312_order(b0: u8, b1: u8) -> i32 {
    if b0 >= 0xb0 && b1 >= 0xa1 { 94 * (b0 as i32 - 0xb0) + b1 as i32 - 0xa1 } else { -1 }
}

fn euckr_order(b0: u8, b1: u8) -> i32 {
    if b0 >= 0xb0 { 94 * (b0 as i32 - 0xb0) + b1 as i32 - 0xa1 } else { -1 }
}

fn big5_order(b0: u8, b1: u8) -> i32 {
    if b0 >= 0xa4 {
        if b1 >= 0xa1 {
            157 * (b0 as i32 - 0xa4) + b1 as i32 - 0xa1 + 63
        } else {
            157 * (b0 as i32 - 0xa4) + b1 as i32 - 0x40
        }
    } else {
        -1
    }
}

fn euctw_order(b0: u8, b1: u8) -> i32 {
    if b0 >= 0xc4 { 94 * (b0 as i32 - 0xc4) + b1 as i32 - 0xa1 } else { -1 }
}

fn sjis_cntx_order(b0: u8, b1: u8) -> i32 {
    if b0 == 0x82 && (0x9f..=0xf1).contains(&b1) { (b1 - 0x9f) as i32 } else { -1 }
}

fn eucjp_cntx_order(b0: u8, b1: u8) -> i32 {
    if b0 == 0xa4 && (0xa1..=0xf3).contains(&b1) { (b1 - 0xa1) as i32 } else { -1 }
}

struct CjkProber {
    coding_sm: CodingStateMachine,
    state: ProbingState,
    context_analyser: Option<JapaneseContextAnalysis>,
    distribution_analyser: CharDistributionAnalysis,
    last_char: [u8; 2],
    charset_name: &'static str,
}

impl CjkProber {
    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        for (i, &b) in buf.iter().enumerate() {
            let coding_state = self.coding_sm.next_state(b);
            if coding_state == E_ITS_ME {
                self.state = ProbingState::FoundIt;
                break;
            }
            if coding_state == E_START {
                let char_len = self.coding_sm.current_char_len;
                let (b0, b1) = if i == 0 {
                    self.last_char[1] = buf[0];
                    (self.last_char[0], self.last_char[1])
                } else {
                    (buf[i - 1], buf[i])
                };
                if let Some(ctx) = &mut self.context_analyser {
                    ctx.handle_one_char(b0, b1, char_len);
                }
                self.distribution_analyser.handle_one_char(b0, b1, char_len);
            }
        }
        self.last_char[0] = buf[buf.len() - 1];
        if self.state == ProbingState::Detecting {
            let enough = match &self.context_analyser {
                Some(ctx) => ctx.got_enough_data(),
                None => self.distribution_analyser.got_enough_data(),
            };
            if enough && self.get_confidence() > SHORTCUT_THRESHOLD {
                self.state = ProbingState::FoundIt;
            }
        }
        self.state
    }

    fn get_confidence(&self) -> f32 {
        let distrib_cf = self.distribution_analyser.get_confidence();
        if let Some(ctx) = &self.context_analyser {
            let contxt_cf = ctx.get_confidence();
            if contxt_cf > distrib_cf { contxt_cf } else { distrib_cf }
        } else {
            distrib_cf
        }
    }
}

struct MbcsGroupProber {
    state: ProbingState,
    utf8: Utf8Prober,
    cjk: [CjkProber; 6],
    best_guess: i32,
    keep_next: usize,
}

impl MbcsGroupProber {
    fn new() -> Self {
        Self {
            state: ProbingState::Detecting,
            utf8: Utf8Prober::new(),
            cjk: [
                CjkProber {
                    coding_sm: CodingStateMachine::new(&SJISSMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: Some(JapaneseContextAnalysis::new(sjis_cntx_order)),
                    distribution_analyser: CharDistributionAnalysis::new(
                        &JIS_CHAR_TO_FREQ_ORDER,
                        JIS_TYPICAL_DISTRIBUTION_RATIO,
                        sjis_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "SHIFT_JIS",
                },
                CjkProber {
                    coding_sm: CodingStateMachine::new(&EUCJPSMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: Some(JapaneseContextAnalysis::new(eucjp_cntx_order)),
                    distribution_analyser: CharDistributionAnalysis::new(
                        &JIS_CHAR_TO_FREQ_ORDER,
                        JIS_TYPICAL_DISTRIBUTION_RATIO,
                        eucjp_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "EUC-JP",
                },
                CjkProber {
                    coding_sm: CodingStateMachine::new(&GB18030SMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: None,
                    distribution_analyser: CharDistributionAnalysis::new(
                        &GB2312_CHAR_TO_FREQ_ORDER,
                        GB2312_TYPICAL_DISTRIBUTION_RATIO,
                        gb2312_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "GB18030",
                },
                CjkProber {
                    coding_sm: CodingStateMachine::new(&EUCKRSMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: None,
                    distribution_analyser: CharDistributionAnalysis::new(
                        &EUCKR_CHAR_TO_FREQ_ORDER,
                        EUCKR_TYPICAL_DISTRIBUTION_RATIO,
                        euckr_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "UHC",
                },
                CjkProber {
                    coding_sm: CodingStateMachine::new(&BIG5SMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: None,
                    distribution_analyser: CharDistributionAnalysis::new(
                        &BIG5_CHAR_TO_FREQ_ORDER,
                        BIG5_TYPICAL_DISTRIBUTION_RATIO,
                        big5_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "BIG5",
                },
                CjkProber {
                    coding_sm: CodingStateMachine::new(&EUCTWSMMODEL),
                    state: ProbingState::Detecting,
                    context_analyser: None,
                    distribution_analyser: CharDistributionAnalysis::new(
                        &EUCTW_CHAR_TO_FREQ_ORDER,
                        EUCTW_TYPICAL_DISTRIBUTION_RATIO,
                        euctw_order,
                    ),
                    last_char: [0, 0],
                    charset_name: "EUC-TW",
                },
            ],
            best_guess: -1,
            keep_next: 0,
        }
    }

    fn feed_slice(&mut self, slice: &[u8]) -> bool {
        if self.utf8.handle_data(slice) == ProbingState::FoundIt {
            self.best_guess = 0;
            self.state = ProbingState::FoundIt;
            return true;
        }
        for i in 0..6 {
            if self.cjk[i].handle_data(slice) == ProbingState::FoundIt {
                self.best_guess = (i + 1) as i32;
                self.state = ProbingState::FoundIt;
                return true;
            }
        }
        false
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        let mut start = 0;
        let mut keep_next = self.keep_next;
        for (pos, &b) in buf.iter().enumerate() {
            if b & 0x80 != 0 {
                if keep_next == 0 {
                    start = pos;
                }
                keep_next = 2;
            } else if keep_next != 0 {
                keep_next -= 1;
                if keep_next == 0 && self.feed_slice(&buf[start..=pos]) {
                    return self.state;
                }
            }
        }
        if keep_next != 0 && self.feed_slice(&buf[start..]) {
            return self.state;
        }
        self.keep_next = keep_next;
        self.state
    }

    fn get_confidence(&mut self) -> f32 {
        match self.state {
            ProbingState::FoundIt => 0.99_f32,
            ProbingState::NotMe => 0.01_f32,
            ProbingState::Detecting => {
                let mut best_conf = 0.0_f32;
                let cf0 = self.utf8.get_confidence();
                if best_conf < cf0 {
                    best_conf = cf0;
                    self.best_guess = 0;
                }
                for i in 0..6 {
                    let cf = self.cjk[i].get_confidence();
                    if best_conf < cf {
                        best_conf = cf;
                        self.best_guess = (i + 1) as i32;
                    }
                }
                best_conf
            }
        }
    }

    fn get_charset_name(&mut self) -> &'static str {
        if self.best_guess == -1 {
            self.get_confidence();
            if self.best_guess == -1 {
                self.best_guess = 0;
            }
        }
        if self.best_guess == 0 { "UTF-8" } else { self.cjk[(self.best_guess - 1) as usize].charset_name }
    }
}

struct SingleByteCharSetProber {
    state: ProbingState,
    model: &'static SequenceModel,
    reversed: bool,
    is_hebrew: bool,
    last_order: u8,
    total_seqs: u32,
    seq_counters: [u32; 4],
    total_char: u32,
    ctrl_char: u32,
    freq_char: u32,
}

impl SingleByteCharSetProber {
    fn new(model: &'static SequenceModel, reversed: bool, is_hebrew: bool) -> Self {
        Self {
            state: ProbingState::Detecting,
            model,
            reversed,
            is_hebrew,
            last_order: 255,
            total_seqs: 0,
            seq_counters: [0; 4],
            total_char: 0,
            ctrl_char: 0,
            freq_char: 0,
        }
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        let fc = self.model.freq_char_count;
        for &b in buf {
            let order = self.model.char_to_order_map[b as usize];
            if order < 250 {
                self.total_char += 1;
            } else if order == 255 {
                self.state = ProbingState::NotMe;
                break;
            } else if order == 254 {
                self.ctrl_char += 1;
            }
            if order < fc {
                self.freq_char += 1;
                if self.last_order < fc {
                    self.total_seqs += 1;
                    let idx = if !self.reversed {
                        (self.last_order as usize) * (fc as usize) + (order as usize)
                    } else {
                        (order as usize) * (fc as usize) + (self.last_order as usize)
                    };
                    self.seq_counters[self.model.precedence_matrix[idx] as usize] += 1;
                }
            }
            self.last_order = order;
        }
        if self.state == ProbingState::Detecting && self.total_seqs > 1024 {
            let cf = self.get_confidence();
            if cf > 0.95_f32 {
                self.state = ProbingState::FoundIt;
            } else if cf < 0.05_f32 {
                self.state = ProbingState::NotMe;
            }
        }
        self.state
    }

    fn get_confidence(&self) -> f32 {
        if self.total_seqs > 0 {
            let mut r = 1.0_f32 * (self.seq_counters[3] as f32) / (self.total_seqs as f32)
                / self.model.typical_positive_ratio;
            r = r * ((self.seq_counters[3] as f32) + (self.seq_counters[2] as f32) / 4.0_f32)
                / (self.total_char as f32);
            r = r * (self.total_char.wrapping_sub(self.ctrl_char) as f32) / (self.total_char as f32);
            r = r * (self.freq_char as f32) / (self.total_char as f32);
            if r >= 1.0_f32 {
                r = 0.99_f32;
            }
            return r;
        }
        0.01_f32
    }
}

struct HebrewProber {
    final_char_logical_score: i32,
    final_char_visual_score: i32,
    prev: u8,
    before_prev: u8,
}

impl HebrewProber {
    fn new() -> Self {
        Self { final_char_logical_score: 0, final_char_visual_score: 0, prev: b' ', before_prev: b' ' }
    }

    fn is_final(c: u8) -> bool {
        matches!(c, 0xea | 0xed | 0xef | 0xf3 | 0xf5)
    }

    fn is_non_final(c: u8) -> bool {
        matches!(c, 0xeb | 0xee | 0xf0 | 0xf4)
    }

    fn handle_data(&mut self, buf: &[u8], logical_state: ProbingState, visual_state: ProbingState) -> ProbingState {
        if logical_state == ProbingState::NotMe && visual_state == ProbingState::NotMe {
            return ProbingState::NotMe;
        }
        for &cur in buf {
            if cur == b' ' {
                if self.before_prev != b' ' {
                    if Self::is_final(self.prev) {
                        self.final_char_logical_score += 1;
                    } else if Self::is_non_final(self.prev) {
                        self.final_char_visual_score += 1;
                    }
                }
            } else if self.before_prev == b' ' && Self::is_final(self.prev) {
                self.final_char_visual_score += 1;
            }
            self.before_prev = self.prev;
            self.prev = cur;
        }
        ProbingState::Detecting
    }

    fn get_charset_name(&self, logical_conf: f32, visual_conf: f32) -> &'static str {
        let finalsub = self.final_char_logical_score - self.final_char_visual_score;
        if finalsub >= 5 {
            return "WINDOWS-1255";
        }
        if finalsub <= -5 {
            return "ISO-8859-8";
        }
        let modelsub = logical_conf - visual_conf;
        if (modelsub as f64) > 0.01 {
            return "WINDOWS-1255";
        }
        if (modelsub as f64) < -0.01 {
            return "ISO-8859-8";
        }
        if finalsub < 0 {
            return "ISO-8859-8";
        }
        "WINDOWS-1255"
    }
}

struct SbcsGroupProber {
    state: ProbingState,
    probers: Vec<Option<SingleByteCharSetProber>>,
    hebrew: HebrewProber,
    is_active: [bool; 100],
    best_guess: i32,
    active_num: i32,
}

impl SbcsGroupProber {
    fn new() -> Self {
        let mut probers = Vec::with_capacity(100);
        for &m in &SBCS_MODELS_BEFORE_HEBREW {
            probers.push(Some(SingleByteCharSetProber::new(m, false, false)));
        }
        probers.push(None); // slot 10: HebrewProber
        probers.push(Some(SingleByteCharSetProber::new(&WIN1255MODEL, false, true))); // slot 11: logical
        probers.push(Some(SingleByteCharSetProber::new(&WIN1255MODEL, true, true))); // slot 12: visual
        for &m in &SBCS_MODELS_AFTER_HEBREW {
            probers.push(Some(SingleByteCharSetProber::new(m, false, false)));
        }
        Self {
            state: ProbingState::Detecting,
            probers,
            hebrew: HebrewProber::new(),
            is_active: [true; 100],
            best_guess: -1,
            active_num: 100,
        }
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        let new_buf = filter_without_english_letters(buf);
        if new_buf.is_empty() {
            return self.state;
        }
        for i in 0..100 {
            if !self.is_active[i] {
                continue;
            }
            let st = if i == 10 {
                let l_state = self.probers[11].as_ref().unwrap().state;
                let v_state = self.probers[12].as_ref().unwrap().state;
                self.hebrew.handle_data(&new_buf, l_state, v_state)
            } else {
                self.probers[i].as_mut().unwrap().handle_data(&new_buf)
            };
            if st == ProbingState::FoundIt {
                self.best_guess = i as i32;
                self.state = ProbingState::FoundIt;
                break;
            } else if st == ProbingState::NotMe {
                self.is_active[i] = false;
                self.active_num -= 1;
                if self.active_num <= 0 {
                    self.state = ProbingState::NotMe;
                    break;
                }
            }
        }
        self.state
    }

    fn get_confidence(&mut self) -> f32 {
        match self.state {
            ProbingState::FoundIt => 0.99_f32,
            ProbingState::NotMe => 0.01_f32,
            ProbingState::Detecting => {
                let mut best_conf = 0.0_f32;
                for i in 0..100 {
                    if !self.is_active[i] {
                        continue;
                    }
                    let cf = match &self.probers[i] {
                        Some(p) => p.get_confidence(),
                        None => 0.0_f32,
                    };
                    if best_conf < cf {
                        best_conf = cf;
                        self.best_guess = i as i32;
                    }
                }
                best_conf
            }
        }
    }

    fn get_charset_name(&mut self) -> &'static str {
        if self.best_guess == -1 {
            self.get_confidence();
            if self.best_guess == -1 {
                self.best_guess = 0;
            }
        }
        let idx = self.best_guess as usize;
        match &self.probers[idx] {
            Some(p) if !p.is_hebrew => p.model.charset_name,
            _ => {
                let l_conf = self.probers[11].as_ref().unwrap().get_confidence();
                let v_conf = self.probers[12].as_ref().unwrap().get_confidence();
                self.hebrew.get_charset_name(l_conf, v_conf)
            }
        }
    }
}

struct Latin1Prober {
    state: ProbingState,
    last_char_class: u8,
    freq_counter: [u32; 4],
}

impl Latin1Prober {
    fn new() -> Self {
        Self { state: ProbingState::Detecting, last_char_class: 1, freq_counter: [0; 4] }
    }

    fn handle_data(&mut self, buf: &[u8]) -> ProbingState {
        let new_buf = filter_with_english_letters(buf);
        for &b in &new_buf {
            let char_class = LATIN1_CHAR_TO_CLASS[b as usize];
            let freq = LATIN1_CLASS_MODEL[(self.last_char_class as usize) * 8 + (char_class as usize)];
            if freq == 0 {
                self.state = ProbingState::NotMe;
                break;
            }
            self.freq_counter[freq as usize] += 1;
            self.last_char_class = char_class;
        }
        self.state
    }

    fn get_confidence(&self) -> f32 {
        if self.state == ProbingState::NotMe {
            return 0.01_f32;
        }
        let total: u32 = self.freq_counter.iter().sum();
        let mut confidence = if total == 0 {
            0.0_f32
        } else {
            let mut c = (self.freq_counter[3] as f32) * 1.0_f32 / (total as f32);
            c -= (self.freq_counter[1] as f32) * 20.0_f32 / (total as f32);
            c
        };
        if confidence < 0.0_f32 {
            confidence = 0.0_f32;
        }
        confidence * 0.50_f32
    }
}

pub struct UniversalDetector {
    input_state: InputState,
    nbsp_found: bool,
    done: bool,
    start: bool,
    got_data: bool,
    last_char: u8,
    detected_charset: Option<&'static str>,
    detected_confidence: f32,
    mbcs: Option<MbcsGroupProber>,
    sbcs: Option<SbcsGroupProber>,
    latin1: Option<Latin1Prober>,
    esc: Option<EscCharSetProber>,
}

impl UniversalDetector {
    pub fn new() -> Self {
        Self {
            input_state: InputState::PureAscii,
            nbsp_found: false,
            done: false,
            start: true,
            got_data: false,
            last_char: 0,
            detected_charset: None,
            detected_confidence: 0.0,
            mbcs: None,
            sbcs: None,
            latin1: None,
            esc: None,
        }
    }

    pub fn handle_data(&mut self, buf: &[u8]) {
        if self.done {
            return;
        }
        if !buf.is_empty() {
            self.got_data = true;
        }
        if self.start {
            self.start = false;
            if buf.len() > 2 {
                match buf[0] {
                    0xEF if buf[1] == 0xBB && buf[2] == 0xBF => {
                        self.detected_charset = Some("UTF-8-SIG");
                        self.detected_confidence = 0.99_f32;
                    }
                    0xFE if buf[1] == 0xFF => {
                        self.detected_charset = Some("UTF-16");
                        self.detected_confidence = 0.99_f32;
                    }
                    0xFF if buf[1] == 0xFE => {
                        if buf.len() > 3 && buf[2] == 0x00 && buf[3] == 0x00 {
                            self.detected_charset = Some("UTF-32");
                            self.detected_confidence = 0.99_f32;
                        } else {
                            self.detected_charset = Some("UTF-16");
                            self.detected_confidence = 0.99_f32;
                        }
                    }
                    0x00 if buf.len() > 3 && buf[1] == 0x00 && buf[2] == 0xFE && buf[3] == 0xFF => {
                        self.detected_charset = Some("UTF-32");
                        self.detected_confidence = 0.99_f32;
                    }
                    _ => {}
                }
            }
            if self.detected_charset.is_some() {
                self.done = true;
                return;
            }
        }

        for &b in buf {
            if b & 0x80 != 0 && b != 0xA0 {
                if self.input_state != InputState::Highbyte {
                    self.input_state = InputState::Highbyte;
                    self.esc = None;
                    if self.mbcs.is_none() {
                        self.mbcs = Some(MbcsGroupProber::new());
                    }
                    if self.sbcs.is_none() {
                        self.sbcs = Some(SbcsGroupProber::new());
                    }
                    if self.latin1.is_none() {
                        self.latin1 = Some(Latin1Prober::new());
                    }
                }
            } else {
                if b == 0xA0 {
                    self.nbsp_found = true;
                } else if self.input_state == InputState::PureAscii
                    && (b == 0x1B || (b == b'{' && self.last_char == b'~'))
                {
                    self.input_state = InputState::EscAscii;
                }
                self.last_char = b;
            }
        }

        match self.input_state {
            InputState::EscAscii => {
                let esc = self.esc.get_or_insert_with(EscCharSetProber::new);
                if esc.handle_data(buf) == ProbingState::FoundIt {
                    self.done = true;
                    self.detected_charset = Some(esc.detected_charset);
                    self.detected_confidence = 0.99_f32;
                }
            }
            InputState::Highbyte => {
                if let Some(mbcs) = &mut self.mbcs
                    && mbcs.handle_data(buf) == ProbingState::FoundIt
                {
                    self.done = true;
                    self.detected_charset = Some(mbcs.get_charset_name());
                    self.detected_confidence = mbcs.get_confidence();
                    return;
                }
                if let Some(sbcs) = &mut self.sbcs
                    && sbcs.handle_data(buf) == ProbingState::FoundIt
                {
                    self.done = true;
                    self.detected_charset = Some(sbcs.get_charset_name());
                    self.detected_confidence = sbcs.get_confidence();
                    return;
                }
                if let Some(latin1) = &mut self.latin1
                    && latin1.handle_data(buf) == ProbingState::FoundIt
                {
                    self.done = true;
                    self.detected_charset = Some("WINDOWS-1252");
                    self.detected_confidence = latin1.get_confidence();
                }
            }
            InputState::PureAscii => {}
        }
    }

    pub fn data_end(&mut self) -> (&'static str, f32) {
        if !self.got_data {
            return ("", 0.0);
        }
        if self.detected_charset.is_none() {
            match self.input_state {
                InputState::EscAscii | InputState::PureAscii => {
                    if self.nbsp_found {
                        self.detected_charset = Some("ISO-8859-1");
                        self.detected_confidence = 1.0_f32;
                    } else {
                        self.detected_charset = Some("ASCII");
                        self.detected_confidence = 1.0_f32;
                    }
                }
                InputState::Highbyte => {}
            }
        }
        if let Some(cs) = self.detected_charset {
            self.done = true;
            return (cs, self.detected_confidence);
        }
        if self.input_state == InputState::Highbyte {
            let mut max_conf = 0.0_f32;
            let mut max_prober = 0;
            if let Some(mbcs) = &mut self.mbcs {
                let c = mbcs.get_confidence();
                if c > max_conf {
                    max_conf = c;
                    max_prober = 0;
                }
            }
            if let Some(sbcs) = &mut self.sbcs {
                let c = sbcs.get_confidence();
                if c > max_conf {
                    max_conf = c;
                    max_prober = 1;
                }
            }
            if let Some(latin1) = &self.latin1 {
                let c = latin1.get_confidence();
                if c > max_conf {
                    max_conf = c;
                    max_prober = 2;
                }
            }
            if max_conf > MINIMUM_THRESHOLD {
                return match max_prober {
                    0 => {
                        let mbcs = self.mbcs.as_mut().unwrap();
                        (mbcs.get_charset_name(), mbcs.get_confidence())
                    }
                    1 => {
                        let sbcs = self.sbcs.as_mut().unwrap();
                        (sbcs.get_charset_name(), sbcs.get_confidence())
                    }
                    _ => ("WINDOWS-1252", self.latin1.as_ref().unwrap().get_confidence()),
                };
            }
        }
        ("", 0.0)
    }
}

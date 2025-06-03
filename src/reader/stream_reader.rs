//! Streaming implementation of [`JsonReader`]

use thiserror::Error;

use self::bytes_value_reader::{
    AsUnicodeEscapeReader, AsUtf8MultibyteReader, BytesValue, BytesValueReader,
};
use super::{json_path::JsonPathPiece, *};
// Ignore false positive for unused import of `json_path!` macro
#[allow(unused_imports)]
use super::json_path::json_path;
use crate::{
    json_number::{consume_json_number, NumberBytesProvider},
    utf8,
};
use alloc::{borrow::ToOwned, format, string::ToString};
use embedded_io_async::{ErrorKind, ErrorType};

#[derive(PartialEq, Clone, Copy, strum::Display, Debug)]
enum PeekedValue {
    ObjectStart,
    ObjectEnd,
    ArrayStart,
    ArrayEnd,
    // Reader state: Opening " has already been consumed
    StringStart,
    NameStart,
    // Reader state: Number has not been consumed yet
    NumberStart,
    Null,
    BooleanTrue,
    BooleanFalse,
}

#[derive(Error, Debug)]
#[error("IO error '{0}' at (roughly) {1}")]
struct ReaderIoError(IoError, JsonReaderPosition);

impl From<ReaderIoError> for ReaderError {
    fn from(value: ReaderIoError) -> Self {
        ReaderError::IoError {
            error: value.0,
            location: value.1,
        }
    }
}

#[derive(Error, Debug)]
enum StringReadingError {
    #[error("syntax error: {0}")]
    SyntaxError(#[from] JsonSyntaxError),
    #[error("{0}")]
    IoError(#[from] ReaderIoError),
}

impl From<StringReadingError> for ReaderError {
    fn from(e: StringReadingError) -> Self {
        match e {
            StringReadingError::SyntaxError(e) => ReaderError::SyntaxError(e),
            StringReadingError::IoError(e) => e.into(),
        }
    }
}

#[derive(PartialEq, Debug)]
enum StackValue {
    Array,
    Object,
}

const READER_BUF_SIZE: usize = 1024;
const INITIAL_VALUE_BYTES_BUF_CAPACITY: usize = 128;

/// A JSON reader implementation which consumes data from a [`Read`]
///
/// This reader internally buffers data so it is normally not necessary to wrap the provided
/// reader in a [`std::io::BufReader`]. However, due to this buffering it should not be
/// attempted to use the provided `Read` after this JSON reader was dropped (in case the
/// `Read` was provided by reference only), unless [`JsonReader::consume_trailing_whitespace`]
/// was called and therefore the end of the `Read` stream was reached. Otherwise due to
/// the buffering it is unpredictable how much additional data this JSON reader has consumed
/// from the `Read`.
///
/// The data provided by the underlying reader is expected to be valid UTF-8 data.
/// The JSON reader methods will return a [`ReaderError::IoError`] if invalid UTF-8 data
/// is detected. A leading byte order mark (BOM) is not allowed.
///
/// If the underlying reader returns an error of kind [`ErrorKind::Interrupted`], this
/// JSON reader will keep retrying to read data.
///
/// # Security
/// Besides UTF-8 validation this JSON reader only implements the following basic security features:
/// - restriction on JSON numbers, see [`ReaderSettings::restrict_number_values`]
/// - nesting depth limit, see [`ReaderSettings::max_nesting_depth`]
///
/// But it does not implement any other security related measures. In particular it does **not**:
///
/// - Impose a limit on the length of the document
///
///   Especially when the JSON data comes from a compressed data stream (such as gzip) large JSON documents
///   could be used for denial of service attacks.
///
/// - Detect duplicate member names
///
///   The JSON specification allows duplicate member names, but does not dictate how to handle
///   them. Different JSON libraries might therefore handle them in inconsistent ways (for example one
///   using the first occurrence, another one using the last), which could be exploited.
///
/// - Impose a limit on the length on member names and string values, or on arrays and objects
///
///   Especially when the JSON data comes from a compressed data stream (such as gzip) large member names
///   and string values or large arrays and objects could be used for denial of service attacks.
///
/// - Impose restrictions on content of member names and string values
///
///   The only restriction is that member names and string values are valid UTF-8 strings, besides
///   that they can contain any code point. They may contain control characters such as the NULL
///   character (`\0`), code points which are not yet assigned a character or invalid graphemes.
///
/// When processing JSON data from an untrusted source, users of this JSON reader must implement protections
/// against the above mentioned security issues themselves.
pub struct JsonStreamReader<R: Read> {
    // When adding more fields to this struct, adjust the Debug implementation below, if necessary
    reader: R,
    /// Buffer containing some bytes read from [`reader`](Self::reader)
    buf: [u8; READER_BUF_SIZE],
    /// Start index (inclusive) at which data in [`buf`](Self::buf) starts
    buf_pos: usize,
    /// Index (exclusive) up to which [`buf`](Self::buf) is filled
    buf_end_pos: usize,
    /// Whether [`buf`](Self::buf) is currently used by a [`BytesRefProvider::ReaderBuf`]
    buf_used_for_bytes_value: bool,
    reached_eof: bool,
    /// Used as scratch buffer to temporarily store string and number values in case they cannot
    /// be served directly from [`buf`](Self::buf)
    value_bytes_buf: Vec<u8>,

    peeked: Option<PeekedValue>,
    /// Whether the current array or object is empty, or at top-level whether
    /// at least one value has been consumed already
    is_empty: bool,
    expects_member_name: bool,
    stack: Vec<StackValue>,
    is_string_value_reader_active: bool,

    line: u64,
    column: u64,
    byte_pos: u64,
    json_path: Option<Vec<JsonPathPiece>>,

    reader_settings: ReaderSettings,
}

// TODO: Is there a way to have `R` only optionally implement `Debug`?
impl<R: Read + Debug> Debug for JsonStreamReader<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("JsonStreamReader");
        debug_struct.field("reader", &self.reader);

        if self.reached_eof {
            debug_struct.field("reached_eof", &"true");
        } else {
            debug_struct.field("buf_count", &(self.buf_end_pos - self.buf_pos));
            let buf_content = &self.buf[self.buf_pos..self.buf_end_pos];

            fn limit_str(s: &str, add_ellipsis: bool) -> String {
                match s.char_indices().nth(45) {
                    None => s.to_owned(),
                    Some((index, _)) => {
                        let s = s[..index].to_owned();
                        if add_ellipsis {
                            format!("{s}...")
                        } else {
                            s
                        }
                    }
                }
            }

            match core::str::from_utf8(buf_content) {
                Ok(buf_string) => {
                    debug_struct.field("buf_str", &limit_str(buf_string, true));
                }
                Err(e) => {
                    let prefix_end = e.valid_up_to();
                    let buf_string_prefix = limit_str(
                        core::str::from_utf8(&buf_content[..prefix_end]).unwrap(),
                        // Don't conditionally add ellipsis; code below will always add ellipsis
                        false,
                    );
                    debug_struct.field("buf_str", &format!("{buf_string_prefix}..."));
                    if buf_string_prefix.len() < 15 {
                        // Include some of the invalid bytes which start after the prefix
                        debug_struct.field(
                            "...buf...",
                            &&buf_content[prefix_end..(prefix_end + 30).min(buf_content.len())],
                        );
                    }
                }
            }
        }

        debug_struct
            .field("peeked", &self.peeked)
            .field("is_empty", &self.is_empty)
            .field("expects_member_name", &self.expects_member_name)
            .field("stack", &self.stack)
            .field(
                "is_string_value_reader_active",
                &self.is_string_value_reader_active,
            )
            .field("line", &self.line)
            .field("column", &self.column)
            .field("byte_pos", &self.byte_pos)
            .field("json_path", &self.json_path)
            .field("reader_settings", &self.reader_settings)
            .finish()
    }
}

/// Settings to customize the JSON reader behavior
///
/// These settings are used by [`JsonStreamReader::new_custom`]. To avoid repeating the
/// default values for unchanged settings `..Default::default()` can be used:
/// ```
/// # use struson::reader::ReaderSettings;
/// ReaderSettings {
///     allow_comments: true,
///     // For all other settings use the default
///     ..Default::default()
/// }
/// # ;
/// ```
#[derive(Clone, Debug)]
pub struct ReaderSettings {
    /// Whether to allow comments in the JSON document
    ///
    /// The JSON specification does not allow comments. However, some programs such as
    /// [Visual Studio Code](https://code.visualstudio.com/docs/languages/json#_json-with-comments)
    /// support comments in JSON files.
    ///
    /// When enabled the following two comment variants can be used where the JSON
    /// specification allows whitespace:
    /// - end of line comments: `// ...`\
    ///   The comment spans to the end of the line (next _CR LF_, _CR_ or _LF_)
    /// - block comments: `/* ... */`\
    ///   The comment ends at the next `*/` and can include line breaks
    ///
    /// Similar to member names and string values, control characters in the range `0x00` to `0x1F`
    /// (inclusive), except for the whitespace characters _tab_ (0x09), _LF_ (0x0A) and _CR_ (0x0D),
    /// are not allowed in comments.
    ///
    /// # Examples
    /// ```json
    /// [
    ///     // This is the first value
    ///     1,
    ///     2 /* and this the second */
    /// ]
    /// ```
    pub allow_comments: bool,

    /// Whether to allow an optional trailing comma in JSON arrays or objects
    ///
    /// The JSON specification requires that there must not be a trailing comma (`,`) after the
    /// last item of a JSON array or the last member of a JSON object. However, especially for
    /// 'pretty printed' JSON used with version control software (such as Git) a trailing comma
    /// reduces the diff when adding items or members. For example with trailing comma:
    /// ```json
    /// [
    ///     1,
    /// ]
    /// ```
    /// Adding a `2` to the array is a single line change:
    /// ```json
    /// [
    ///     1,
    ///     2, // <-- only changed line
    /// ]
    /// ```
    /// Whereas without a trailing comma adding a `2` would change two lines: `1` is changed to
    /// `1,` and a new line is added for the `2`.
    ///
    /// **Important:** Since trailing commas are not allowed by the specification, different JSON reader
    /// implementations might handle trailing commas differently. For example some treat them as implicit
    /// `null` value in JSON arrays instead of just ignoring them.
    pub allow_trailing_comma: bool,

    /// Whether to allow multiple top-level values, for example `true [] 1` (3 top-level values)
    ///
    /// Normally a JSON document is expected to contain only a single top-level value, but there
    /// might be use cases where supporting multiple top-level values can be useful, for example
    /// when reading JSON data in the [JSON Lines](https://github.com/wardi/jsonlines) format,
    /// that is, a stream of multiple JSON values separated by line breaks.
    ///
    /// It is recommended to separate the values using whitespace (space, tab or line breaks).
    /// If there is no whitespace between the values it is unspecified whether parsing will succeed.
    /// For example the string `truefalse` will likely be rejected and not parsed as JSON values
    /// `true` and `false`.
    pub allow_multiple_top_level: bool,

    /// Whether to track the JSON path while parsing
    ///
    /// The JSON path is reported for [error locations](JsonReaderPosition::path) to make debugging
    /// easier. Disabling path tracking can therefore make troubleshooting malformed JSON data more
    /// difficult, but it might on the other hand improve performance.
    ///
    /// This setting has no effect on the JSON parsing behavior, it only affects the information included
    /// for errors.
    pub track_path: bool,

    /// Maximum nesting depth
    ///
    /// The maximum nesting depth specifies how many nested JSON arrays or objects may
    /// be started before returning [`ReaderError::MaxNestingDepthExceeded`].
    /// For example a maximum nesting depth of 2 allows to start one JSON array or object
    /// and within that another nested array or object, such as `{"outer": {"inner": 1}}`.
    /// Trying to read any further nested JSON array or object inside that will return an error.\
    /// The value `None` means there is no limit.
    ///
    /// The maximum nesting depth tries to protect against deeply nested JSON data which
    /// could lead to a stack overflow during reading, so setting this to `None` or high
    /// values should be done with care. While the implementation of [`JsonStreamReader`]
    /// does not use recursion and will therefore likely not encounter a stack overflow,
    /// users of it are probably going to use recursion in some form.
    pub max_nesting_depth: Option<u32>,

    /// Whether to restrict which JSON number values are supported
    ///
    /// The JSON specification does not impose any restrictions on the size or precision of JSON numbers.
    /// This means values such as `1e4000` or `1e-4000` are valid JSON numbers. However, parsing such numbers
    /// or performing calculations with them later on can lead to performance issues and can potentially
    /// be exploited for denial of service attacks, especially when they are parsed as arbitrary-precision
    /// "big integer" / "big decimal".
    ///
    /// When this setting is enabled, exponent values smaller than -99, larger than 99 (e.g. `5e100`)
    /// and numbers whose string representation has more than 100 characters will be rejected and a
    /// [`ReaderError::UnsupportedNumberValue`] is returned. Otherwise, when disabled, all JSON
    /// number values are allowed.
    ///
    /// Note that depending on the use case even these restrictions might not be enough. If necessary
    /// users have to implement additional restrictions themselves, or if possible parse the number as
    /// fixed size integral number such as `u32` instead of "big integer" types.
    pub restrict_number_values: bool,
}

const DEFAULT_MAX_NESTING_DEPTH: u32 = 128; // update documentation when changing this value

impl Default for ReaderSettings {
    /// Creates the default JSON reader settings
    ///
    /// - [comments](Self::allow_comments): disallowed
    /// - [trailing comma](Self::allow_trailing_comma): disallowed
    /// - [multiple top-level values](Self::allow_multiple_top_level): disallowed
    /// - [track JSON path](Self::track_path): enabled
    /// - [max nesting depth](Self::max_nesting_depth): 128
    /// - [restrict number values](Self::restrict_number_values): enabled
    ///
    /// These defaults are compliant with the JSON specification.
    fn default() -> Self {
        ReaderSettings {
            allow_comments: false,
            allow_trailing_comma: false,
            allow_multiple_top_level: false,
            track_path: true,
            max_nesting_depth: Some(DEFAULT_MAX_NESTING_DEPTH),
            restrict_number_values: true,
        }
    }
}

// Implementation with public methods
impl<R: Read> JsonStreamReader<R> {
    /// Creates a JSON reader with [default settings](ReaderSettings::default)
    pub fn new(reader: R) -> Self {
        JsonStreamReader::new_custom(reader, ReaderSettings::default())
    }

    /// Creates a JSON reader with custom settings
    ///
    /// The settings can be used to customize which JSON data the reader accepts and to allow
    /// JSON data which is considered invalid by the JSON specification.
    pub fn new_custom(reader: R, reader_settings: ReaderSettings) -> Self {
        let initial_nesting_capacity = 16;
        Self {
            reader,
            buf: [0_u8; READER_BUF_SIZE],
            buf_pos: 0,
            buf_end_pos: 0,
            buf_used_for_bytes_value: false,
            reached_eof: false,
            value_bytes_buf: Vec::with_capacity(INITIAL_VALUE_BYTES_BUF_CAPACITY),
            peeked: None,
            is_empty: true,
            expects_member_name: false,
            stack: Vec::with_capacity(initial_nesting_capacity),
            is_string_value_reader_active: false,
            line: 0,
            column: 0,
            byte_pos: 0,
            json_path: if reader_settings.track_path {
                Some(Vec::with_capacity(initial_nesting_capacity))
            } else {
                None
            },
            reader_settings,
        }
    }

    /// Gets a mutable reference to the underlying reader
    ///
    /// This should only be needed rarely, for advanced use cases only. The reader should not
    /// be used for determining the byte position of the JSON reader, since it might buffer
    /// not yet processed data internally. Instead the [`JsonReaderPosition::data_pos`] of the
    /// [`current_position`](Self::current_position) should be used for that.
    ///
    /// ----
    ///
    /// **🔬 Experimental**\
    /// This method is currently experimental, please provide feedback about how you are using it
    /// [here](https://github.com/Marcono1234/struson/issues/25).
    pub fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }
}

// Implementation with error utility methods, and methods for inspecting JSON structure state
impl<R: Read> JsonStreamReader<R> {
    fn create_error_location(&self) -> JsonReaderPosition {
        self.current_position(true)
    }

    fn create_syntax_value_error<T>(
        &self,
        syntax_error_kind: SyntaxErrorKind,
    ) -> Result<T, ReaderError> {
        Err(ReaderError::SyntaxError(JsonSyntaxError {
            kind: syntax_error_kind,
            location: self.create_error_location(),
        }))
    }

    fn is_behind_top_level(&self) -> bool {
        !self.is_empty && self.stack.is_empty()
    }

    fn is_in_array(&self) -> bool {
        self.stack.last() == Some(&StackValue::Array)
    }

    fn is_in_object(&self) -> bool {
        self.stack.last() == Some(&StackValue::Object)
    }

    fn expects_member_value(&self) -> bool {
        self.is_in_object() && !self.expects_member_name
    }
}

// Implementation with low level byte reading methods
impl<R: Read> JsonStreamReader<R> {
    /// Fills the buffer, starting at `start_pos`
    ///
    /// The [`buf_pos`] is set to `start_pos`. If the end of the input has been
    /// reached `false` is returned.
    async fn fill_buffer(&mut self, start_pos: usize) -> Result<bool, ReaderIoError> {
        if self.reached_eof {
            return Ok(false);
        }
        debug_assert!(self.buf_pos >= self.buf_end_pos);
        debug_assert!(start_pos < self.buf.len());

        if self.buf_used_for_bytes_value {
            panic!("Unexpected: Cannot refill buf because it holds a bytes value; report this to the Struson maintainers");
        }

        self.buf_pos = start_pos;
        loop {
            let read_bytes_count = match self.reader.read(&mut self.buf[start_pos..]).await {
                Ok(read_bytes_count) => read_bytes_count,
                // Retry if interrupted
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(ReaderIoError(
                        IoError {
                            kind: e.kind(),
                            message: String::new(),
                        },
                        self.create_error_location(),
                    ))
                }
            };
            self.buf_end_pos = start_pos + read_bytes_count;
            break;
        }
        if self.buf_end_pos == start_pos {
            self.reached_eof = true;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Ensures that the buffer is not empty
    ///
    /// If the buffer is currently empty it is refilled start at index 0.
    /// If the end of the input has been reached, `false` is returned.
    /// Otherwise the caller can read the next byte from [`buf`] starting
    /// at [`start_pos`].
    async fn ensure_non_empty_buffer(&mut self) -> Result<bool, ReaderIoError> {
        if self.buf_pos < self.buf_end_pos {
            return Ok(true);
        }
        self.fill_buffer(0).await
    }

    /// Peeks at the next byte without consuming it
    ///
    /// Returns `None` if the end of the input has been reached.
    async fn peek_byte(&mut self) -> Result<Option<u8>, ReaderIoError> {
        if self.ensure_non_empty_buffer().await? {
            Ok(Some(self.buf[self.buf_pos]))
        } else {
            Ok(None)
        }
    }

    /// Skips the last byte returned by [`peek_byte`]
    fn skip_peeked_byte(&mut self) {
        debug_assert!(self.buf_pos < self.buf_end_pos);
        self.buf_pos += 1;
    }

    /// Reads the next byte, returning an error if the end of the
    /// input has been reached
    async fn read_byte(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, StringReadingError> {
        if let Some(b) = self.peek_byte().await? {
            self.skip_peeked_byte();
            Ok(b)
        } else {
            Err(JsonSyntaxError {
                kind: eof_error_kind,
                location: self.create_error_location(),
            })?
        }
    }
}

// Implementation with whitespace skipping logic
impl<R: Read> JsonStreamReader<R> {
    async fn skip_to<P: Fn(u8) -> bool>(
        &mut self,
        stop_predicate: P,
        eof_error_kind: Option<SyntaxErrorKind>,
    ) -> Result<(), ReaderError> {
        let mut has_cr = false;

        while let Some(byte) = self.peek_byte().await? {
            if stop_predicate(byte) {
                return Ok(());
            }
            if matches!(byte, 0x00..=0x1F) && !matches!(byte, b'\t' | b'\n' | b'\r') {
                return Err(JsonSyntaxError {
                    // This error kind is possibly a bit misleading for comments in JSON because
                    // escape sequences don't exist there, but probably not worth it having a
                    // separate error kind just for control chars in comments
                    kind: SyntaxErrorKind::NotEscapedControlCharacter,
                    location: self.create_error_location(),
                })?;
            }
            self.skip_peeked_byte();

            match byte {
                b'\n' => {
                    // Count \r\n (Windows line break) as only one line break
                    if !has_cr {
                        self.column = 0;
                        self.line += 1;
                    }
                    self.byte_pos += 1;
                }
                b'\r' => {
                    self.column = 0;
                    self.line += 1;
                    self.byte_pos += 1;
                }
                // Skip ASCII character
                _ if utf8::is_1byte(byte) => {
                    self.column += 1;
                    self.byte_pos += 1;
                }
                _ => {
                    // Validate the UTF-8 data, but ignore it
                    let mut buf = [0_u8; utf8::MAX_BYTES_PER_CHAR];
                    let bytes = self.read_utf8_multibyte(byte, &mut buf).await?;
                    self.column += 1;
                    self.byte_pos += bytes.len() as u64;
                }
            }
            // Set this after each iteration so that "\r   \n" is not considered a single line break
            has_cr = byte == b'\r';
        }

        match eof_error_kind {
            None => Ok(()),
            Some(error_kind) => self.create_syntax_value_error(error_kind),
        }
    }

    async fn skip_to_line_comment_end(
        &mut self,
        eof_error_kind: Option<SyntaxErrorKind>,
    ) -> Result<(), ReaderError> {
        self.skip_to(|byte| matches!(byte, b'\n' | b'\r'), eof_error_kind)
            .await
        // Don't consume LF or CR, let skip_whitespace handle it
    }

    async fn skip_to_block_comment_end(&mut self) -> Result<(), ReaderError> {
        loop {
            self.skip_to(
                |byte| byte == b'*',
                Some(SyntaxErrorKind::BlockCommentNotClosed),
            )
            .await?;
            // Consume the '*'
            self.column += 1;
            self.byte_pos += 1;
            self.skip_peeked_byte();

            let byte = match self.peek_byte().await? {
                None => {
                    return self.create_syntax_value_error(SyntaxErrorKind::BlockCommentNotClosed)
                }
                Some(byte) => byte,
            };

            if byte == b'/' {
                self.skip_peeked_byte();
                self.column += 1;
                self.byte_pos += 1;
                return Ok(());
            }
            // Otherwise continue loop searching for next '*', but don't consume the peeked
            // byte yet, it might be the next '*', e.g. for "/***/"
        }
    }

    async fn skip_whitespace(
        &mut self,
        eof_error_kind: Option<SyntaxErrorKind>,
    ) -> Result<Option<u8>, ReaderError> {
        // Run this in loop because when comment is skipped have to skip whitespace (and comments) again
        loop {
            self.skip_to(
                // Skip whitespace and line breaks
                |byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r'),
                None,
            )
            .await?;

            let byte = match self.peek_byte().await? {
                Some(byte) => byte,
                None => {
                    return eof_error_kind.map_or(Ok(None), |error_kind| {
                        self.create_syntax_value_error(error_kind)
                    });
                }
            };

            if byte == b'/' {
                if !self.reader_settings.allow_comments {
                    return self.create_syntax_value_error(SyntaxErrorKind::CommentsNotEnabled);
                }
                self.skip_peeked_byte();
                self.column += 1;
                self.byte_pos += 1;

                match self.read_byte(SyntaxErrorKind::IncompleteComment).await? {
                    b'*' => {
                        self.column += 1;
                        self.byte_pos += 1;
                        self.skip_to_block_comment_end().await?;
                    }
                    b'/' => {
                        self.column += 1;
                        self.byte_pos += 1;
                        self.skip_to_line_comment_end(eof_error_kind).await?;
                    }
                    _ => {
                        return self.create_syntax_value_error(SyntaxErrorKind::IncompleteComment);
                    }
                }
            } else {
                // Non whitespace or comment, return
                return Ok(Some(byte));
            }
        }
    }

    async fn skip_whitespace_no_eof(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, ReaderError> {
        // unwrap should be safe, skip_whitespace made sure that EOF has not been reached
        Ok(self.skip_whitespace(Some(eof_error_kind)).await?.unwrap())
    }
}

// Implementation with peeking (and consumption of literals) logic
impl<R: Read> JsonStreamReader<R> {
    fn verify_value_separator(
        &self,
        byte: u8,
        error_kind: SyntaxErrorKind,
    ) -> Result<(), JsonSyntaxError> {
        match byte {
            // Note: Also includes ':' even though that is not a valid value separator to get more accurate errors
            b',' | b']' | b'}' | b' ' | b'\t' | b'\n' | b'\r' | b'/' | b':' => Ok(()),
            _ => Err(JsonSyntaxError {
                kind: error_kind,
                location: self.create_error_location(),
            }),
        }
    }

    async fn consume_literal(&mut self, literal: &str) -> Result<(), ReaderError> {
        for expected_byte in literal.bytes() {
            let byte = self.read_byte(SyntaxErrorKind::InvalidLiteral).await?;
            if byte != expected_byte {
                return self.create_syntax_value_error(SyntaxErrorKind::InvalidLiteral);
            }
        }

        // Make sure there are no misleading chars directly afterwards, e.g. "truey"
        if let Some(byte) = self.peek_byte().await? {
            self.verify_value_separator(byte, SyntaxErrorKind::TrailingDataAfterLiteral)?;
        }

        // Note: Don't adjust `self.column` yet, is done when peeked value is actually consumed
        Ok(())
    }

    async fn peek_internal_optional(&mut self) -> Result<Option<PeekedValue>, ReaderError> {
        if self.is_string_value_reader_active {
            panic!("Incorrect reader usage: Cannot peek when string value reader is active");
        }

        if self.peeked.is_some() {
            return Ok(self.peeked);
        }

        if self.is_behind_top_level() && !self.reader_settings.allow_multiple_top_level {
            panic!("Incorrect reader usage: Cannot peek when top-level value has already been consumed and multiple top-level values are not enabled in settings");
        }
        if self.expects_member_value() {
            // Finish member name which has just been consumed before
            self.after_name().await?;
        }

        let byte = self.skip_whitespace(None).await?;
        if byte.is_none() {
            return Ok(None);
        }
        let mut byte = byte.unwrap();

        let mut has_trailing_comma = false;
        let mut comma_line = 0;
        let mut comma_column = 0;
        let mut comma_byte_pos = 0;
        let can_have_comma = !self.is_empty && (self.is_in_array() || self.expects_member_name);

        if byte == b',' {
            if !can_have_comma {
                return self.create_syntax_value_error(SyntaxErrorKind::UnexpectedComma);
            }
            self.skip_peeked_byte();
            comma_line = self.line;
            comma_column = self.column;
            comma_byte_pos = self.byte_pos;
            self.column += 1;
            self.byte_pos += 1;
            has_trailing_comma = true;

            byte = self
                .skip_whitespace_no_eof(SyntaxErrorKind::IncompleteDocument)
                .await?;
        }

        let mut advance_reader: bool = true;
        let peeked = if self.expects_member_name {
            match byte {
                b'}' => PeekedValue::ObjectEnd,
                b'"' => PeekedValue::NameStart,
                _ => {
                    return self.create_syntax_value_error(
                        SyntaxErrorKind::ExpectingMemberNameOrObjectEnd,
                    );
                }
            }
        } else {
            match byte {
                b'[' => PeekedValue::ArrayStart,
                b']' => {
                    if !self.is_in_array() {
                        return self
                            .create_syntax_value_error(SyntaxErrorKind::UnexpectedClosingBracket);
                    }
                    PeekedValue::ArrayEnd
                }
                b'{' => PeekedValue::ObjectStart,
                b'}' => {
                    return self
                        .create_syntax_value_error(SyntaxErrorKind::UnexpectedClosingBracket);
                }
                b'"' => PeekedValue::StringStart,
                b'-' | b'0'..=b'9' => {
                    // Don't advance yet to preserve first number char for later
                    advance_reader = false;
                    PeekedValue::NumberStart
                }
                b'n' => {
                    self.consume_literal("null").await?;
                    advance_reader = false; // consume_literal already advanced reader
                    PeekedValue::Null
                }
                b't' => {
                    self.consume_literal("true").await?;
                    advance_reader = false; // consume_literal already advanced reader
                    PeekedValue::BooleanTrue
                }
                b'f' => {
                    self.consume_literal("false").await?;
                    advance_reader = false; // consume_literal already advanced reader
                    PeekedValue::BooleanFalse
                }
                b',' => {
                    // Comma has already been handled above
                    return self.create_syntax_value_error(SyntaxErrorKind::UnexpectedComma);
                }
                b':' => {
                    return self.create_syntax_value_error(SyntaxErrorKind::UnexpectedColon);
                }
                _ => {
                    return self.create_syntax_value_error(SyntaxErrorKind::MalformedJson);
                }
            }
        };

        if peeked == PeekedValue::ArrayEnd || peeked == PeekedValue::ObjectEnd {
            if has_trailing_comma && !self.reader_settings.allow_trailing_comma {
                // Report location of comma
                self.line = comma_line;
                self.column = comma_column;
                self.byte_pos = comma_byte_pos;
                return self.create_syntax_value_error(SyntaxErrorKind::TrailingCommaNotEnabled);
            }
        } else if can_have_comma && !has_trailing_comma {
            return self.create_syntax_value_error(SyntaxErrorKind::MissingComma);
        }

        if advance_reader {
            self.skip_peeked_byte();
        }

        self.peeked = Some(peeked);
        Ok(self.peeked)
    }

    async fn peek_internal(&mut self) -> Result<PeekedValue, ReaderError> {
        self.peek_internal_optional().await?.map_or_else(
            // Handle EOF
            || {
                let eof_as_unexpected_structure =
                    self.is_behind_top_level() && self.reader_settings.allow_multiple_top_level;
                if eof_as_unexpected_structure {
                    Err(ReaderError::UnexpectedStructure {
                        kind: UnexpectedStructureKind::FewerElementsThanExpected,
                        location: self.create_error_location(),
                    })
                } else {
                    self.create_syntax_value_error(SyntaxErrorKind::IncompleteDocument)
                }
            },
            Ok,
        )
    }

    fn map_peeked(&self, peeked: PeekedValue) -> Result<ValueType, ReaderError> {
        Ok(match peeked {
            PeekedValue::ObjectStart => ValueType::Object,
            PeekedValue::ObjectEnd | PeekedValue::NameStart => {
                unreachable!(
                    "peek() should have already panicked when object member name is expected"
                );
            }
            PeekedValue::ArrayStart => ValueType::Array,
            PeekedValue::ArrayEnd => {
                return Err(ReaderError::UnexpectedStructure {
                    kind: UnexpectedStructureKind::FewerElementsThanExpected,
                    location: self.create_error_location(),
                });
            }
            PeekedValue::StringStart => ValueType::String,
            PeekedValue::NumberStart => ValueType::Number,
            PeekedValue::Null => ValueType::Null,
            PeekedValue::BooleanTrue | PeekedValue::BooleanFalse => ValueType::Boolean,
        })
    }

    fn consume_peeked(&mut self) {
        let peeked_length = match self.peeked.take().unwrap() {
            PeekedValue::ObjectStart => 1,
            PeekedValue::ObjectEnd => 1,
            PeekedValue::ArrayStart => 1,
            PeekedValue::ArrayEnd => 1,
            PeekedValue::StringStart | PeekedValue::NameStart => 1, // opening double quote is consumed by peek()
            PeekedValue::NumberStart => 0, // first number char is not consumed during peek()
            PeekedValue::Null => 4,
            PeekedValue::BooleanTrue => 4,
            PeekedValue::BooleanFalse => 5,
        };
        self.column += peeked_length;
        // Peeked value types above consist only of ASCII chars; therefore can treat length as byte count
        self.byte_pos += peeked_length;
    }
}

// Implementation with general value consumption methods
impl<R: Read> JsonStreamReader<R> {
    async fn start_expected_value_type(
        &mut self,
        expected: ValueType,
        check_depth: bool,
    ) -> Result<PeekedValue, ReaderError> {
        if self.expects_member_name {
            panic!("Incorrect reader usage: Cannot read value when expecting member name");
        }

        let peeked_internal = self.peek_internal().await?;
        let peeked = self.map_peeked(peeked_internal)?;

        return if peeked == expected {
            if check_depth {
                // Check nesting depth before consuming token, so that error location points
                // at token instead of behind it
                if let Some(max_nesting_depth) = self.reader_settings.max_nesting_depth {
                    if self.stack.len() as u32 >= max_nesting_depth {
                        return Err(ReaderError::MaxNestingDepthExceeded {
                            max_nesting_depth,
                            location: self.create_error_location(),
                        });
                    }
                }
            }

            self.consume_peeked();
            Ok(peeked_internal)
        } else {
            Err(ReaderError::UnexpectedValueType {
                expected,
                actual: peeked,
                location: self.create_error_location(),
            })
        };
    }

    async fn on_container_start(
        &mut self,
        expected_value_type: ValueType,
        stack_value: StackValue,
    ) -> Result<(), ReaderError> {
        self.start_expected_value_type(expected_value_type, true)
            .await?;

        self.stack.push(stack_value);
        // The new container is initially empty
        self.is_empty = true;
        Ok(())
    }

    fn on_container_end(&mut self) {
        self.stack.pop();
        if let Some(ref mut json_path) = self.json_path {
            json_path.pop();
        }

        self.on_value_end();
    }

    fn on_value_end(&mut self) {
        // Update array path
        if self.is_in_array() {
            if let Some(ref mut json_path) = self.json_path {
                match json_path.last_mut().unwrap() {
                    JsonPathPiece::ArrayItem(index) => *index += 1,
                    _ => unreachable!("Path should be array item"),
                }
            }
        }

        // After value was consumed indicate that object member name is expected next
        if self.is_in_object() {
            self.expects_member_name = true;
        }

        // Enclosing container is not empty since this method call here is processing its child
        self.is_empty = false;
    }
}

// TODO: Maybe try to find a cleaner solution than having this separate trait
trait Utf8MultibyteReader {
    async fn read_byte(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, StringReadingError>;

    fn create_error_location(&self) -> JsonReaderPosition;

    fn invalid_utf8_err<'a>(&self) -> Result<&'a [u8], StringReadingError> {
        Err(StringReadingError::IoError(ReaderIoError(
            IoError {
                kind: ErrorKind::InvalidData,
                message: String::from("invalid UTF-8 data"),
            },
            self.create_error_location(),
        )))
    }

    /// Reads a UTF-8 char consisting of multiple bytes
    ///
    /// `byte0` is the first byte which has already been read by the caller. `destination_buf` is
    /// used by this method to store all the UTF-8 bytes. A slice of it containing the read bytes
    /// is returned as result; it includes `byte0` as first element.
    async fn read_utf8_multibyte<'a>(
        &mut self,
        byte0: u8,
        destination_buf: &'a mut [u8; utf8::MAX_BYTES_PER_CHAR],
    ) -> Result<&'a [u8], StringReadingError> {
        let result_slice: &'a mut [u8];
        let byte1 = self.read_byte(SyntaxErrorKind::IncompleteDocument).await?;

        if !utf8::is_continuation(byte1) {
            return self.invalid_utf8_err();
        }

        if utf8::is_2byte_start(byte0) {
            if !utf8::is_valid_2bytes(byte0, byte1) {
                return self.invalid_utf8_err();
            }

            result_slice = &mut destination_buf[..2];
            result_slice[0] = byte0;
            result_slice[1] = byte1;
        } else {
            let byte2 = self.read_byte(SyntaxErrorKind::IncompleteDocument).await?;

            if !utf8::is_continuation(byte2) {
                return self.invalid_utf8_err();
            }

            if utf8::is_3byte_start(byte0) {
                if !utf8::is_valid_3bytes(byte0, byte1, byte2) {
                    return self.invalid_utf8_err();
                }

                result_slice = &mut destination_buf[..3];
                result_slice[0] = byte0;
                result_slice[1] = byte1;
                result_slice[2] = byte2;
            } else if utf8::is_4byte_start(byte0) {
                let byte3 = self.read_byte(SyntaxErrorKind::IncompleteDocument).await?;

                if !utf8::is_continuation(byte3) {
                    return self.invalid_utf8_err();
                }
                if !utf8::is_valid_4bytes(byte0, byte1, byte2, byte3) {
                    return self.invalid_utf8_err();
                }

                result_slice = &mut destination_buf[..4];
                result_slice[0] = byte0;
                result_slice[1] = byte1;
                result_slice[2] = byte2;
                result_slice[3] = byte3;
            } else {
                return self.invalid_utf8_err();
            }
        }
        Ok(result_slice)
    }
}

// Implementing this directly for JsonStreamReader should be harmless, since the methods of this
// trait implemented below simply delegate to the JsonStreamReader ones
impl<R: Read> Utf8MultibyteReader for JsonStreamReader<R> {
    async fn read_byte(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, StringReadingError> {
        self.read_byte(eof_error_kind).await
    }

    fn create_error_location(&self) -> JsonReaderPosition {
        self.create_error_location()
    }
}

/// A `char` which was represented by one or two (in case of surrogate pairs)
/// JSON Unicode escape sequences
struct UnicodeEscapeChar {
    c: char,
    /// Number of chars which were part of the escape sequence; does not include the
    /// initial `\u` of the first escape sequence
    consumed_chars_count: u32,
}

// TODO: Maybe try to find a cleaner solution than having this separate trait
trait UnicodeEscapeReader {
    async fn read_byte(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, StringReadingError>;

    fn create_error_location(&self) -> JsonReaderPosition;

    fn parse_unicode_escape_hex_digit(&self, digit: u8) -> Result<u32, StringReadingError> {
        match digit {
            b'0'..=b'9' => Ok(u32::from(digit - b'0')),
            b'a'..=b'f' => Ok(u32::from(digit - b'a' + 10)),
            b'A'..=b'F' => Ok(u32::from(digit - b'A' + 10)),
            _ => Err(JsonSyntaxError {
                kind: SyntaxErrorKind::MalformedEscapeSequence,
                location: self.create_error_location(),
            })?,
        }
    }

    async fn read_hex_byte(&mut self) -> Result<u32, StringReadingError> {
        let byte = self
            .read_byte(SyntaxErrorKind::MalformedEscapeSequence)
            .await?;
        self.parse_unicode_escape_hex_digit(byte)
    }

    async fn read_unicode_escape(&mut self) -> Result<u32, StringReadingError> {
        let d1 = self.read_hex_byte().await?;
        let d2 = self.read_hex_byte().await?;
        let d3 = self.read_hex_byte().await?;
        let d4 = self.read_hex_byte().await?;

        Ok(d4 | (d3 << 4) | (d2 << 8) | (d1 << 12))
    }

    /// Reads a Unicode-escaped char
    ///
    /// The caller should have already read the initial `\u` prefix.
    async fn read_unicode_escape_char(&mut self) -> Result<UnicodeEscapeChar, StringReadingError> {
        let mut c = self.read_unicode_escape().await?;
        // 4 for `XXXX`, the prefix `\u` has already been accounted for by the caller
        let mut consumed_chars_count = 4;

        // Unpaired low surrogate
        if matches!(c, 0xDC00..=0xDFFF) {
            return Err(JsonSyntaxError {
                kind: SyntaxErrorKind::UnpairedSurrogatePairEscapeSequence,
                location: self.create_error_location(),
            })?;
        }
        // If char is high surrogate, expect Unicode-escaped low surrogate
        if matches!(c, 0xD800..=0xDBFF) {
            if !(self
                .read_byte(SyntaxErrorKind::UnpairedSurrogatePairEscapeSequence)
                .await?
                == b'\\'
                && self
                    .read_byte(SyntaxErrorKind::UnpairedSurrogatePairEscapeSequence)
                    .await?
                    == b'u')
            {
                return Err(JsonSyntaxError {
                    kind: SyntaxErrorKind::UnpairedSurrogatePairEscapeSequence,
                    location: self.create_error_location(),
                })?;
            }
            let c2 = self.read_unicode_escape().await?;
            consumed_chars_count += 6; // \uXXXX
            if !matches!(c2, 0xDC00..=0xDFFF) {
                return Err(JsonSyntaxError {
                    kind: SyntaxErrorKind::UnpairedSurrogatePairEscapeSequence,
                    location: self.create_error_location(),
                })?;
            }

            c = (((c - 0xD800) << 10) | (c2 - 0xDC00)) + 0x10000;
        }

        // unwrap() here should be safe since checks above made sure this is a valid Rust `char`
        let c = char::from_u32(c).unwrap();
        Ok(UnicodeEscapeChar {
            c,
            consumed_chars_count,
        })
    }
}

// Implementing this directly for JsonStreamReader should be harmless, since the methods of this
// trait implemented below simply delegate to the JsonStreamReader ones
impl<R: Read> UnicodeEscapeReader for JsonStreamReader<R> {
    async fn read_byte(
        &mut self,
        eof_error_kind: SyntaxErrorKind,
    ) -> Result<u8, StringReadingError> {
        self.read_byte(eof_error_kind).await
    }

    fn create_error_location(&self) -> JsonReaderPosition {
        self.create_error_location()
    }
}

mod bytes_value_reader {
    use core::mem::replace;

    use super::*;

    /// Reader for a 'value' read from the underlying `JsonStreamReader`
    ///
    /// The 'value' can for example be a JSON string value or the string representation of
    /// a JSON number. The main purpose of this struct is to allow retrieving either a
    /// `str` or a `String` later for that value, but hiding the implementation details
    /// of how this value is stored by `JsonStreamReader`.
    /*
     * TODO: Write dedicated unit tests for this which covers corner cases? Or is this covered well enough
     * already by tests for `next_str`, `next_string`, ...
     */
    pub(super) struct BytesValueReader<'j, R: Read> {
        pub(super) json_reader: &'j mut JsonStreamReader<R>,
        /// Whether [`JsonStreamReader::value_bytes_buf`] is used to store the value;
        /// in that case the start of the value might already be in `value_bytes_buf`,
        /// while the remainder might be in [`JsonStreamReader::buf`], with [`buf_value_start`]
        /// being the start and [`JsonStreamReader::buf_pos`] being the end (exclusive)
        is_using_bytes_buf: bool,
        /// Start index of the value (or its remainder) in [`JsonStreamReader::buf`], inclusive;
        /// the end index is [`JsonStreamReader::buf_pos`] (exclusive)
        buf_value_start: usize,
        /// Whether the final byte of the value should be skipped
        ///
        /// This is a special case because unlike for [`skip_previous_byte`] it is not necessary
        /// to save the so far read bytes to [`JsonStreamReader::value_bytes_buf`].
        skip_final_byte: bool,
    }

    /// A bytes value, which is either a borrowed `&[u8]` which can be requested on demand
    /// from the [`JsonStreamReader`], or an owned `Vec<u8>`.
    ///
    /// The caller who created this value must have validated that the collected bytes are
    /// valid UTF-8 data.
    #[derive(Debug)]
    pub(super) enum BytesValue {
        /// A borrowed `&[u8]`
        BytesRef(BytesRefProvider),
        /// An owned `Vec<u8>`
        Vec(Vec<u8>),
    }

    /*
     * == Implementation note ==
     * Cleaner alternative to this would have been to store a reference to the `&[u8]` value
     * in BytesValue, e.g.:
     * ```
     * enum BytesValue<'j> {
     *     Slice(&'j [u8]),
     *     Vec(Vec<u8>),
     * }
     * ```
     * It would then have been transparent where that bytes slice came from (reader buf or bytes value buf),
     * and the method returning the BytesValue could have used the same lifetime for it as for the
     * JsonStreamReader. It would have also allowed to have a `StringValue` enum with a similar structure,
     * containing either a `&'j str` or a `String`.
     *
     * However, this would then have caused issues for users of BytesValue because while they were holding
     * a reference to the BytesValue they were also holding a reference to the JsonStreamReader and therefore
     * the borrow checker would not have allowed any other usage of JsonStreamReader.
     * Therefore this approach delays the access to the `&[u8]` until it is actually requested.
     *
     * Maybe there is a cleaner solution to this though.
     */
    /// Provides access to a `&[u8]` value.
    #[derive(Debug)]
    pub(super) enum BytesRefProvider {
        /// Value is backed by [`JsonStreamReader::buf`]
        ReaderBuf { start: usize, end: usize },
        /// Value is backed by [`JsonStreamReader::value_bytes_buf`]
        BytesValueBuf,
    }

    impl BytesRefProvider {
        fn get_bytes_ref<'j, R: Read>(&self, json_reader: &'j JsonStreamReader<R>) -> &'j [u8] {
            match self {
                BytesRefProvider::ReaderBuf { start, end } => &json_reader.buf[*start..*end],
                BytesRefProvider::BytesValueBuf => &json_reader.value_bytes_buf,
            }
        }

        fn get_str<'j, R: Read>(&self, json_reader: &'j JsonStreamReader<R>) -> &'j str {
            let bytes = self.get_bytes_ref(json_reader);
            // Should be safe; creator of BytesRefProvider should have verified that bytes are valid
            utf8::to_str_unchecked(bytes)
        }
    }

    impl BytesValue {
        /// Gets the read bytes as `String`
        pub(super) fn get_string<R: Read>(self, json_reader: &mut JsonStreamReader<R>) -> String {
            match self {
                BytesValue::BytesRef(b) => {
                    // `get_string` consumes `self` so afterwards value cannot be obtained from `buf` anymore
                    json_reader.buf_used_for_bytes_value = false;
                    b.get_str(json_reader).to_owned()
                }
                // Should be safe; creator of BytesRefProvider should have verified that bytes are valid
                BytesValue::Vec(v) => utf8::to_string_unchecked(v),
            }
        }

        /// Same as [`get_str`](Self::get_str), except that this method does not consume `self`
        pub(super) fn get_str_peek<'j, R: Read>(
            &self,
            json_reader: &'j JsonStreamReader<R>,
        ) -> &'j str {
            match self {
                BytesValue::BytesRef(b) => b.get_str(json_reader),
                // Should be unreachable because when `str` is expected, `true` should have been provided
                // as `requires_borrowed` value, in which case result won't be BytesValue::Vec
                BytesValue::Vec(_) => {
                    panic!("get_str should only be called when `requires_borrowed=true`")
                }
            }
        }

        /// Gets the read bytes as `str`
        ///
        /// Must only be called if the `BytesValue` was obtained from [`BytesValueReader::get_bytes`] being
        /// called with `requires_borrow=true`.
        pub(super) fn get_str<R: Read>(self, json_reader: &mut JsonStreamReader<R>) -> &str {
            // `get_str` consumes `self` so afterwards value cannot be obtained from `buf` anymore
            json_reader.buf_used_for_bytes_value = false;
            self.get_str_peek(json_reader)
        }
    }

    impl<'j, R: Read> BytesValueReader<'j, R> {
        pub(super) fn new(json_reader: &'j mut JsonStreamReader<R>) -> Self {
            let old_buf_start = json_reader.buf_pos;
            // Move buffer content to start of array to make sure complete buffer size is available
            if old_buf_start > 0 {
                let old_buf_end = json_reader.buf_end_pos;
                json_reader.buf.copy_within(old_buf_start..old_buf_end, 0);
                json_reader.buf_pos = 0;
                json_reader.buf_end_pos = old_buf_end - old_buf_start;
            }
            json_reader.value_bytes_buf.clear();
            // Shrink buffer in case it got excessively large during the previous usage
            // TODO: Maybe perform this in `on_value_end` and `after_name` instead
            json_reader
                .value_bytes_buf
                .shrink_to(INITIAL_VALUE_BYTES_BUF_CAPACITY * 2);

            BytesValueReader {
                json_reader,
                is_using_bytes_buf: false,
                buf_value_start: 0,
                skip_final_byte: false,
            }
        }

        /// Peeks at the next byte without consuming it
        ///
        /// To consume the byte afterwards, call [`consume_peeked_byte`].
        /// If the end of the input has been reached and `eof_error_kind` is `None`
        /// `None` is returned. Otherwise an error is returned.
        pub(super) async fn peek_byte_optional(
            &mut self,
            eof_error_kind: Option<SyntaxErrorKind>,
        ) -> Result<Option<u8>, StringReadingError> {
            debug_assert!(
                !self.skip_final_byte,
                "Must not read more bytes after final byte was marked as skipped"
            );

            let end_pos = self.json_reader.buf_end_pos;

            if self.json_reader.buf_pos < end_pos {
                let byte = self.json_reader.buf[self.json_reader.buf_pos];
                Ok(Some(byte))
            }
            // Else check if can / have to start at index 0 of `json_reader.buf`
            else if self.is_using_bytes_buf
                || self.json_reader.buf_pos >= self.json_reader.buf.len()
            {
                // Save all bytes which should be kept
                if self.buf_value_start < end_pos {
                    let bytes = &self.json_reader.buf[self.buf_value_start..end_pos];
                    self.json_reader.value_bytes_buf.extend_from_slice(bytes);
                    self.is_using_bytes_buf = true;
                }

                self.buf_value_start = 0;

                if self.json_reader.fill_buffer(0).await? {
                    Ok(Some(self.json_reader.buf[0]))
                } else if let Some(eof_error_kind) = eof_error_kind {
                    Err(JsonSyntaxError {
                        kind: eof_error_kind,
                        location: self.json_reader.create_error_location(),
                    })?
                } else {
                    Ok(None)
                }
            }
            // Else continue filling `json_reader.buf` behind previously read data
            else {
                #[allow(clippy::collapsible_else_if)]
                if self.json_reader.fill_buffer(end_pos).await? {
                    Ok(Some(self.json_reader.buf[end_pos]))
                } else if let Some(eof_error_kind) = eof_error_kind {
                    Err(JsonSyntaxError {
                        kind: eof_error_kind,
                        location: self.json_reader.create_error_location(),
                    })?
                } else {
                    Ok(None)
                }
            }
        }

        /// Reads the next byte
        pub(super) async fn read_byte(
            &mut self,
            eof_error_kind: SyntaxErrorKind,
        ) -> Result<u8, StringReadingError> {
            let byte = self
                .peek_byte_optional(Some(eof_error_kind))
                .await
                .map(|b| b.unwrap())?;
            self.consume_peeked_byte();
            Ok(byte)
        }

        /// Consumes the previous peeked byte which has just been peeked at using [`peek_byte_optional`]
        #[inline(always)]
        pub(super) fn consume_peeked_byte(&mut self) {
            self.json_reader.buf_pos += 1;
        }

        /// Skips the previous byte which has just been read using [`read_byte`]
        pub(super) fn skip_previous_byte(&mut self) {
            debug_assert!(
                !self.skip_final_byte,
                "Cannot skip after byte has already been marked as skipped final byte"
            );

            // End position (exclusive) of the value; `buf_pos` is the index of the next not yet consumed byte
            let end_pos = self.json_reader.buf_pos;

            // If no bytes have been kept so far, can just increase index
            if self.buf_value_start + 1 == end_pos {
                self.buf_value_start += 1;
            }
            // Otherwise need to save the previous part of the value
            else {
                // `end_pos - 1` because the current byte should be skipped
                let bytes = &self.json_reader.buf[self.buf_value_start..end_pos - 1];
                self.json_reader.value_bytes_buf.extend_from_slice(bytes);
                self.is_using_bytes_buf = true;
                self.buf_value_start = end_pos;
            }
        }

        /// Skips the final byte of the value, which has just been read using [`read_byte`]. Afterwards no
        /// further bytes may be read and [`push_bytes`] should be called.
        /// This method is intended for values where the final delimiter has been read, which should not
        /// be part of the value, for example the closing `"` of a string.
        pub(super) fn skip_final_byte(&mut self) {
            self.skip_final_byte = true;
        }

        /// Pushes bytes into the value buffer
        ///
        /// This can be used in combination with [`skip_previous_byte`] to replace bytes
        /// in the value, by first skipping the original bytes and then pushing a replacement,
        /// for example for JSON string escape sequences.
        pub(super) fn push_bytes(&mut self, bytes: &[u8]) {
            let end_pos = self.json_reader.buf_pos;
            if self.buf_value_start < end_pos {
                // Push remainder into buffer
                self.json_reader
                    .value_bytes_buf
                    .extend_from_slice(&self.json_reader.buf[self.buf_value_start..end_pos]);
                self.buf_value_start = end_pos;
            }

            self.is_using_bytes_buf = true;
            self.json_reader.value_bytes_buf.extend_from_slice(bytes);
        }

        /// Gets the final bytes value. Must be called at most once.
        /*
         * Ideally would use `self` instead of `&mut self` to prevent calling this method multiple times
         * by accident, but in some cases need access to `json_reader` from field of this struct afterwards
         * to obtain string value from `BytesValue`; therefore for now keep this as `&mut self`
         */
        pub(super) fn get_bytes(&mut self, requires_borrowed: bool) -> BytesValue {
            let mut end_pos = self.json_reader.buf_pos;
            if self.skip_final_byte {
                end_pos -= 1;
            }

            if self.is_using_bytes_buf {
                // Push remainder into buffer
                self.json_reader
                    .value_bytes_buf
                    .extend_from_slice(&self.json_reader.buf[self.buf_value_start..end_pos]);

                if requires_borrowed {
                    // Indicate that value is in `value_bytes_buf`
                    BytesValue::BytesRef(BytesRefProvider::BytesValueBuf)
                } else {
                    let bytes = replace(
                        &mut self.json_reader.value_bytes_buf,
                        Vec::with_capacity(INITIAL_VALUE_BYTES_BUF_CAPACITY),
                    );
                    BytesValue::Vec(bytes)
                }
            } else {
                // Indicate that `buf` contains bytes value, to prevent accidental modification
                debug_assert!(!self.json_reader.buf_used_for_bytes_value);
                self.json_reader.buf_used_for_bytes_value = true;

                BytesValue::BytesRef(BytesRefProvider::ReaderBuf {
                    start: self.buf_value_start,
                    end: end_pos,
                })
            }
        }
    }

    // 'newtype pattern' to avoid leaking `read_byte` implementation directly for BytesValueReader (and to avoid ambiguity)
    pub(super) struct AsUtf8MultibyteReader<'a, 'j, R: Read>(
        pub(super) &'a mut BytesValueReader<'j, R>,
    );
    impl<R: Read> Utf8MultibyteReader for AsUtf8MultibyteReader<'_, '_, R> {
        async fn read_byte(
            &mut self,
            eof_error_kind: SyntaxErrorKind,
        ) -> Result<u8, StringReadingError> {
            // Note: Don't need to skip byte because it will be part of the final value
            self.0.read_byte(eof_error_kind).await
        }

        fn create_error_location(&self) -> JsonReaderPosition {
            self.0.json_reader.create_error_location()
        }
    }

    // 'newtype pattern' to avoid leaking `read_byte` implementation directly for BytesValueReader (and to avoid ambiguity)
    pub(super) struct AsUnicodeEscapeReader<'a, 'j, R: Read>(
        pub(super) &'a mut BytesValueReader<'j, R>,
    );
    impl<R: Read> UnicodeEscapeReader for AsUnicodeEscapeReader<'_, '_, R> {
        async fn read_byte(
            &mut self,
            eof_error_kind: SyntaxErrorKind,
        ) -> Result<u8, StringReadingError> {
            let byte = self.0.read_byte(eof_error_kind).await?;
            // Skip byte which is part of escape sequence; should not be in the final value
            self.0.skip_previous_byte();
            Ok(byte)
        }

        fn create_error_location(&self) -> JsonReaderPosition {
            self.0.json_reader.create_error_location()
        }
    }
}

// Implementation with string and object member name reading methods
impl<R: Read> JsonStreamReader<R> {
    /// Reads the next character of a member name or string value
    ///
    /// If it is an unescaped `"` returns true. Otherwise passes the bytes of the char
    /// (1 - 4 bytes) to the given consumer and returns false.
    async fn read_string_bytes<C: FnMut(u8)>(
        &mut self,
        consumer: &mut C,
    ) -> Result<bool, StringReadingError> {
        let byte = self.read_byte(SyntaxErrorKind::IncompleteDocument).await?;

        let mut reached_end = false;
        let mut consumed_chars_count = 1;
        let mut consumed_bytes_count = 1;
        match byte {
            // Read escape sequence
            b'\\' => {
                let byte = self
                    .read_byte(SyntaxErrorKind::MalformedEscapeSequence)
                    .await?;
                consumed_chars_count += 1;
                consumed_bytes_count += 1;

                match byte {
                    b'"' | b'\\' | b'/' => consumer(byte),
                    b'b' => consumer(0x08),
                    b'f' => consumer(0x0C),
                    b'n' => consumer(b'\n'),
                    b'r' => consumer(b'\r'),
                    b't' => consumer(b'\t'),
                    b'u' => {
                        let UnicodeEscapeChar {
                            c,
                            consumed_chars_count: escape_consumed_chars_count,
                        } = self.read_unicode_escape_char().await?;
                        consumed_chars_count += escape_consumed_chars_count as u64;
                        // Treat as byte count because Unicode escape only uses single byte ASCII chars
                        consumed_bytes_count += escape_consumed_chars_count as u64;

                        let mut char_encode_buf = [0_u8; utf8::MAX_BYTES_PER_CHAR];
                        let encoded_char = c.encode_utf8(&mut char_encode_buf);
                        for b in encoded_char.as_bytes() {
                            consumer(*b);
                        }
                    }
                    _ => {
                        return Err(JsonSyntaxError {
                            kind: SyntaxErrorKind::UnknownEscapeSequence,
                            location: self.create_error_location(),
                        })?
                    }
                }
            }
            b'"' => {
                reached_end = true;
            }
            // Control characters must be written as Unicode escape
            0x00..=0x1F => {
                return Err(JsonSyntaxError {
                    kind: SyntaxErrorKind::NotEscapedControlCharacter,
                    location: self.create_error_location(),
                })?;
            }
            // Non-control ASCII characters
            0x20..=0x7F => {
                consumer(byte);
            }
            // Read and validate multibyte UTF-8 data
            _ => {
                let mut buf = [0_u8; utf8::MAX_BYTES_PER_CHAR];
                let bytes = self.read_utf8_multibyte(byte, &mut buf).await?;
                for b in bytes {
                    consumer(*b);
                }
                // - 1 because `byte0` has already been counted at start of `match`
                consumed_bytes_count += bytes.len() as u64 - 1;
            }
        }

        // Update location afterwards, so in case of error, start position of escape sequence or multi-byte UTF-8 char is reported
        self.column += consumed_chars_count;
        self.byte_pos += consumed_bytes_count;
        Ok(reached_end)
    }

    async fn read_all_string_bytes<C: FnMut(u8)>(
        &mut self,
        consumer: &mut C,
    ) -> Result<(), StringReadingError> {
        loop {
            let reached_end = self.read_string_bytes(consumer).await?;
            if reached_end {
                return Ok(());
            }
        }
    }

    async fn skip_all_string_bytes(&mut self) -> Result<(), StringReadingError> {
        self.read_all_string_bytes(&mut |_| {}).await
    }

    /// Reads a JSON string value (either a JSON string or a member name) and returns a `BytesValue`
    /// for access to it. The `BytesValue` is guaranteed to refer to valid UTF-8 bytes.
    ///
    /// `requires_borrowed` indicates whether the caller requires obtaining the string value
    /// as `str` later by calling [`BytesValue::get_str`].
    async fn read_string(
        &mut self,
        requires_borrowed: bool,
    ) -> Result<BytesValue, StringReadingError> {
        let mut bytes_reader = BytesValueReader::new(self);
        let read_bytes: BytesValue;

        loop {
            let byte = bytes_reader
                .read_byte(SyntaxErrorKind::IncompleteDocument)
                .await?;
            match byte {
                // Read escape sequence
                b'\\' => {
                    // Exclude the '\' from the value
                    bytes_reader.skip_previous_byte();
                    let byte = bytes_reader
                        .read_byte(SyntaxErrorKind::MalformedEscapeSequence)
                        .await?;

                    match byte {
                        b'"' | b'\\' | b'/' => {} // do nothing, keep the literal char as part of the `bytes_reader` value
                        b'b' => {
                            // Skip the 'b' and instead push the represented char
                            bytes_reader.skip_previous_byte();
                            bytes_reader.push_bytes(&[0x08]);
                        }
                        b'f' => {
                            // Skip the 'f' and instead push the represented char
                            bytes_reader.skip_previous_byte();
                            bytes_reader.push_bytes(&[0x0C]);
                        }
                        b'n' => {
                            // Skip the 'n' and instead push the represented char
                            bytes_reader.skip_previous_byte();
                            bytes_reader.push_bytes(b"\n");
                        }
                        b'r' => {
                            // Skip the 'r' and instead push the represented char
                            bytes_reader.skip_previous_byte();
                            bytes_reader.push_bytes(b"\r");
                        }
                        b't' => {
                            // Skip the 't' and instead push the represented char
                            bytes_reader.skip_previous_byte();
                            bytes_reader.push_bytes(b"\t");
                        }
                        b'u' => {
                            // Skip the 'u'
                            bytes_reader.skip_previous_byte();

                            let UnicodeEscapeChar {
                                c,
                                consumed_chars_count,
                            } = AsUnicodeEscapeReader(&mut bytes_reader)
                                .read_unicode_escape_char()
                                .await?;
                            bytes_reader.json_reader.column += consumed_chars_count as u64;
                            // Treat as byte count because Unicode escape only uses single byte ASCII chars
                            bytes_reader.json_reader.byte_pos += consumed_chars_count as u64;
                            let mut char_encode_buf = [0_u8; utf8::MAX_BYTES_PER_CHAR];
                            let encoded_char = c.encode_utf8(&mut char_encode_buf);
                            bytes_reader.push_bytes(encoded_char.as_bytes());
                        }
                        _ => {
                            return Err(JsonSyntaxError {
                                kind: SyntaxErrorKind::UnknownEscapeSequence,
                                location: bytes_reader.json_reader.create_error_location(),
                            })?
                        }
                    }
                    // After escape sequence was successfully read, update location information;
                    // otherwise error message would point at the middle of escape sequence
                    bytes_reader.json_reader.column += 2;
                    bytes_reader.json_reader.byte_pos += 2;
                }
                b'"' => {
                    bytes_reader.json_reader.column += 1;
                    bytes_reader.json_reader.byte_pos += 1;
                    // Don't include the '"' in the value
                    bytes_reader.skip_final_byte();
                    read_bytes = bytes_reader.get_bytes(requires_borrowed);
                    break;
                }
                // Control characters must be written as Unicode escape
                0x00..=0x1F => {
                    return Err(JsonSyntaxError {
                        kind: SyntaxErrorKind::NotEscapedControlCharacter,
                        location: bytes_reader.json_reader.create_error_location(),
                    })?;
                }
                // Non-control ASCII characters
                0x20..=0x7F => {
                    bytes_reader.json_reader.column += 1;
                    bytes_reader.json_reader.byte_pos += 1;
                    // Note: bytes_reader will keep the byte in the final value because it is not skipped here
                }
                // Read and validate multibyte UTF-8 data
                // Note: Technically this could be omitted, ASCII and multibyte UTF-8 could be treated the same
                // and UTF-8 validation from Rust standard library could be used, however, then it would not be easily
                // possible anymore to track the character location for error messages because it would not be clear
                // how many bytes are part of a character
                _ => {
                    let mut buf = [0_u8; utf8::MAX_BYTES_PER_CHAR];
                    // Ignore bytes here, bytes_reader will keep the bytes in the final value because they are not skipped here
                    let bytes = AsUtf8MultibyteReader(&mut bytes_reader)
                        .read_utf8_multibyte(byte, &mut buf)
                        .await?;
                    bytes_reader.json_reader.column += 1;
                    bytes_reader.json_reader.byte_pos += bytes.len() as u64;
                }
            }
        }

        // Code above manually performed UTF-8 validation, `read_bytes` should be safe to use for obtaining strings
        Ok(read_bytes)
    }

    // Note: This is split into `before_name` and `after_name` to allow both `next_name` and `skip_name`
    // to reuse this code
    async fn before_name(&mut self) -> Result<(), ReaderError> {
        if !self.expects_member_name {
            panic!("Incorrect reader usage: Cannot consume member name when not expecting it");
        }
        if self.is_string_value_reader_active {
            panic!("Incorrect reader usage: Cannot consume member name when string value reader is active");
        }

        if !self.has_next().await? {
            return Err(ReaderError::UnexpectedStructure {
                kind: UnexpectedStructureKind::FewerElementsThanExpected,
                location: self.create_error_location(),
            });
        }

        self.expects_member_name = false;
        // `has_next` call above peeked at start of member name; consume opening double quote here now
        self.consume_peeked();
        Ok(())
    }

    async fn after_name(&mut self) -> Result<(), ReaderError> {
        let byte = self
            .skip_whitespace_no_eof(SyntaxErrorKind::MissingColon)
            .await?;
        return if byte == b':' {
            self.skip_peeked_byte();
            self.column += 1;
            self.byte_pos += 1;
            Ok(())
        } else {
            self.create_syntax_value_error(SyntaxErrorKind::MissingColon)
        };
    }
}

// Implementation for number reading
trait NumberBytesReader<T, E>: NumberBytesProvider<E> {
    /// Gets the number of consumed bytes
    fn get_consumed_bytes_count(&self) -> u32;
    /// Returns whether this reader restricts the read number (length or exponent)
    fn restricts_number(&self) -> bool;
    /// If [`restricts_number`] returns true, gets the number string for error reporting in case
    /// it does not match the restrictions.
    fn get_number_string_for_error(self) -> String;
    fn get_result(self) -> T;
}

// Using macro here to avoid issues with borrow checker; probably not the cleanest solution
// TODO: Try to find a cleaner solution without using macro?
macro_rules! collect_next_number_bytes {
    ( |$self:ident| $reader_creator:expr ) => {{
        $self
            .start_expected_value_type(ValueType::Number, false)
            .await?;

        // unwrap() is safe because start_expected_value_type already peeked at first number byte
        let first_byte = $self.peek_byte().await?.unwrap();
        let mut reader = $reader_creator;
        let number_result = consume_json_number(&mut reader, first_byte).await?;
        let exponent_digits_count = match number_result {
            None => return $self.create_syntax_value_error(SyntaxErrorKind::MalformedNumber),
            Some(exponent_digits_count) => exponent_digits_count,
        };

        let consumed_bytes = reader.get_consumed_bytes_count();
        if reader.restricts_number() {
            // >= e100, <= e-100 or complete number longer than 100 chars
            if exponent_digits_count > 2 || consumed_bytes > 100 {
                return Err(ReaderError::UnsupportedNumberValue {
                    number: reader.get_number_string_for_error(),
                    location: $self.create_error_location(),
                });
            }
        }

        let result = reader.get_result();
        $self.column += consumed_bytes as u64;
        $self.byte_pos += consumed_bytes as u64;
        // Make sure there are no misleading chars directly afterwards, e.g. "123f"
        if let Some(byte) = $self.peek_byte().await? {
            $self.verify_value_separator(byte, SyntaxErrorKind::TrailingDataAfterNumber)?
        }

        $self.on_value_end();
        result
    }};
}

impl<R: Read> JsonStreamReader<R> {
    /// Reads a JSON number and returns a `BytesValue` for access to its string representation.
    /// The `BytesValue` is guaranteed to refer to valid UTF-8 bytes.
    ///
    /// `requires_borrowed` indicates whether the caller requires obtaining the string representation
    /// as `str` later by calling [`BytesValue::get_str`].
    async fn read_number_bytes(
        &mut self,
        requires_borrowed: bool,
    ) -> Result<BytesValue, ReaderError> {
        let restrict_number = self.reader_settings.restrict_number_values;

        Ok(collect_next_number_bytes!(|self| NumberBytesValueReader {
            reader: BytesValueReader::new(self),
            consumed_bytes: 0,
            restrict_number,
            requires_borrowed_result: requires_borrowed,
        }))
    }
}

struct NumberBytesValueReader<'j, R: Read> {
    reader: BytesValueReader<'j, R>,
    consumed_bytes: u32,
    restrict_number: bool,
    requires_borrowed_result: bool,
}
impl<R: Read> NumberBytesProvider<ReaderError> for NumberBytesValueReader<'_, R> {
    async fn consume_current_peek_next(&mut self) -> Result<Option<u8>, ReaderError> {
        // Note: The first byte was not actually read by `BytesValueReader`, instead it was peeked by creator
        // of NumberBytesValueReader. However, consume it here to include it in the final value.
        self.reader.consume_peeked_byte();
        self.consumed_bytes += 1;
        Ok(self.reader.peek_byte_optional(None).await?)
    }
}
impl<R: Read> NumberBytesReader<BytesValue, ReaderError> for NumberBytesValueReader<'_, R> {
    fn get_consumed_bytes_count(&self) -> u32 {
        self.consumed_bytes
    }

    fn restricts_number(&self) -> bool {
        self.restrict_number
    }

    fn get_number_string_for_error(mut self) -> String {
        self.reader
            // No UTF-8 checks are needed because JSON number consists only of ASCII chars
            .get_bytes(false)
            .get_string(self.reader.json_reader)
    }

    fn get_result(mut self) -> BytesValue {
        // No UTF-8 checks are needed because JSON number consists only of ASCII chars
        self.reader.get_bytes(self.requires_borrowed_result)
    }
}

struct SkippingNumberBytesReader<'j, R: Read> {
    json_reader: &'j mut JsonStreamReader<R>,
    consumed_bytes: u32,
}
impl<R: Read> NumberBytesProvider<ReaderIoError> for SkippingNumberBytesReader<'_, R> {
    async fn consume_current_peek_next(&mut self) -> Result<Option<u8>, ReaderIoError> {
        // Should not fail since last peek_byte() succeeded
        self.json_reader.skip_peeked_byte();
        self.consumed_bytes += 1;
        self.json_reader.peek_byte().await
    }
}
impl<R: Read> NumberBytesReader<(), ReaderIoError> for SkippingNumberBytesReader<'_, R> {
    fn get_consumed_bytes_count(&self) -> u32 {
        self.consumed_bytes
    }

    fn restricts_number(&self) -> bool {
        // Don't restrict number values while skipping
        false
    }

    fn get_number_string_for_error(self) -> String {
        unreachable!("Should not be called since restricts_number() returns false")
    }

    fn get_result(self) {}
}

impl<R: Read> JsonReader for JsonStreamReader<R> {
    async fn peek(&mut self) -> Result<ValueType, ReaderError> {
        if self.expects_member_name {
            panic!("Incorrect reader usage: Cannot peek value when expecting member name");
        }
        let peeked = self.peek_internal().await?;
        self.map_peeked(peeked)
    }

    async fn begin_array(&mut self) -> Result<(), ReaderError> {
        self.on_container_start(ValueType::Array, StackValue::Array)
            .await?;

        if let Some(ref mut json_path) = self.json_path {
            json_path.push(JsonPathPiece::ArrayItem(0));
        }

        // Clear this because it is only relevant for objects; will be restored when entering parent object (if any) again
        self.expects_member_name = false;
        Ok(())
    }

    async fn end_array(&mut self) -> Result<(), ReaderError> {
        if !self.is_in_array() {
            panic!("Incorrect reader usage: Cannot end array when not inside array");
        }
        let peeked = self.peek_internal().await?;
        if peeked != PeekedValue::ArrayEnd {
            return Err(ReaderError::UnexpectedStructure {
                kind: UnexpectedStructureKind::MoreElementsThanExpected,
                location: self.create_error_location(),
            });
        }
        self.consume_peeked();
        self.on_container_end();
        Ok(())
    }

    async fn begin_object(&mut self) -> Result<(), ReaderError> {
        self.on_container_start(ValueType::Object, StackValue::Object)
            .await?;

        if let Some(ref mut json_path) = self.json_path {
            // Push a placeholder which is replaced once the name of the first member is read
            // Important: When changing this placeholder in the future also have to update documentation mentioning to it
            json_path.push(JsonPathPiece::ObjectMember("<?>".to_owned()));
        }

        self.expects_member_name = true;
        Ok(())
    }

    async fn next_name_owned(&mut self) -> Result<String, ReaderError> {
        self.before_name().await?;

        let name = self.read_string(false).await?.get_string(self);

        if let Some(ref mut json_path) = self.json_path {
            match json_path.last_mut().unwrap() {
                JsonPathPiece::ObjectMember(path_name) => path_name.clone_from(&name),
                _ => unreachable!("Path should be object member"),
            }
        }
        Ok(name)
        // Consuming `:` after name is delayed until member value is consumed
    }

    async fn next_name(&mut self) -> Result<&str, ReaderError> {
        self.before_name().await?;

        let name_bytes = self.read_string(true).await?;

        if self.json_path.is_some() {
            // TODO: Not ideal that this causes `core::str::from_utf8` to be called twice, once here and once
            // for return value; not sure though if this can be solved
            let name = name_bytes.get_str_peek(self).to_owned();
            // `unwrap` call here is safe due to `is_some` check above (cannot easily rewrite this because there
            // would be two mutable borrows of `self` then at the same time)
            match self.json_path.as_mut().unwrap().last_mut().unwrap() {
                JsonPathPiece::ObjectMember(path_name) => *path_name = name,
                _ => unreachable!("Path should be object member"),
            }
        }
        Ok(name_bytes.get_str(self))
        // Consuming `:` after name is delayed until member value is consumed; otherwise if it was done
        // here it might refill the reader buffer and accidentally overwrite the value of `name_bytes`
    }

    async fn end_object(&mut self) -> Result<(), ReaderError> {
        if !self.is_in_object() {
            panic!("Incorrect reader usage: Cannot end object when not inside object");
        }
        if self.expects_member_value() {
            panic!("Incorrect reader usage: Cannot end object when member value is expected");
        }
        let peeked = self.peek_internal().await?;
        if peeked != PeekedValue::ObjectEnd {
            return Err(ReaderError::UnexpectedStructure {
                kind: UnexpectedStructureKind::MoreElementsThanExpected,
                location: self.create_error_location(),
            });
        }
        self.consume_peeked();
        // Clear expects_member_name in case current container is now an array; on_container_end() call
        // below (respectively on_value_end() called by it) will set expects_member_name again if
        // enclosing container is an object
        self.expects_member_name = false;
        self.on_container_end();
        Ok(())
    }

    async fn next_bool(&mut self) -> Result<bool, ReaderError> {
        let value = match self
            .start_expected_value_type(ValueType::Boolean, false)
            .await?
        {
            PeekedValue::BooleanTrue => true,
            PeekedValue::BooleanFalse => false,
            // Call to start_expected_value_type should have verified type
            _ => unreachable!("Peeked value is not a boolean"),
        };
        self.on_value_end();
        Ok(value)
    }

    async fn next_null(&mut self) -> Result<(), ReaderError> {
        self.start_expected_value_type(ValueType::Null, false)
            .await?;
        self.on_value_end();
        Ok(())
    }

    async fn has_next(&mut self) -> Result<bool, ReaderError> {
        if self.expects_member_value() {
            panic!("Incorrect reader usage: Cannot check for next element when member value is expected");
        }

        let peeked: PeekedValue;
        if self.stack.is_empty() {
            if self.is_empty {
                panic!("Incorrect reader usage: Cannot check for next element when top-level value has not been started");
            } else if !self.reader_settings.allow_multiple_top_level {
                panic!("Incorrect reader usage: Cannot check for multiple top-level values when not enabled in the reader settings");
            } else {
                peeked = match self.peek_internal_optional().await? {
                    None => return Ok(false),
                    Some(p) => p,
                }
            }
        } else {
            peeked = self.peek_internal().await?;
        }
        debug_assert!(
            !self.expects_member_name
                || peeked == PeekedValue::NameStart
                || peeked == PeekedValue::ObjectEnd
        );

        Ok((peeked != PeekedValue::ArrayEnd) && (peeked != PeekedValue::ObjectEnd))
    }

    async fn skip_name(&mut self) -> Result<(), ReaderError> {
        self.before_name().await?;

        if self.json_path.is_some() {
            // Similar to `next_name` implementation, except that `name` can directly be moved to
            // json_path piece instead of having to be cloned
            let name = self.read_string(false).await?.get_string(self);

            // `unwrap` call here is safe due to `is_some` check above (cannot easily rewrite this because there
            // would be two mutable borrows of `self` then at the same time)
            match self.json_path.as_mut().unwrap().last_mut().unwrap() {
                JsonPathPiece::ObjectMember(path_name) => *path_name = name,
                _ => unreachable!("Path should be object member"),
            }
        } else {
            self.skip_all_string_bytes().await?;
        }
        Ok(())
        // Consuming `:` after name is delayed until member value is consumed
    }

    async fn skip_value(&mut self) -> Result<(), ReaderError> {
        if self.expects_member_name {
            panic!("Incorrect reader usage: Cannot skip value when expecting member name");
        }

        let mut depth: u32 = 0;
        loop {
            if depth > 0 && !self.has_next().await? {
                if self.is_in_array() {
                    self.end_array().await?;
                } else {
                    self.end_object().await?;
                }
                depth -= 1;
            } else {
                if self.expects_member_name {
                    self.skip_name().await?;
                }

                match self.peek().await? {
                    ValueType::Array => {
                        self.begin_array().await?;
                        depth += 1;
                    }
                    ValueType::Object => {
                        self.begin_object().await?;
                        depth += 1;
                    }
                    ValueType::String => {
                        self.start_expected_value_type(ValueType::String, false)
                            .await?;
                        self.skip_all_string_bytes().await?;
                        self.on_value_end();
                    }
                    ValueType::Number => {
                        collect_next_number_bytes!(|self| SkippingNumberBytesReader {
                            json_reader: self,
                            consumed_bytes: 0,
                        });
                    }
                    ValueType::Boolean => {
                        self.next_bool().await?;
                    }
                    ValueType::Null => {
                        self.next_null().await?;
                    }
                }
            }

            if depth == 0 {
                break;
            }
        }

        Ok(())
    }

    async fn next_string(&mut self) -> Result<String, ReaderError> {
        self.start_expected_value_type(ValueType::String, false)
            .await?;
        let result = self.read_string(false).await?.get_string(self);
        self.on_value_end();
        Ok(result)
    }

    async fn next_str(&mut self) -> Result<&str, ReaderError> {
        self.start_expected_value_type(ValueType::String, false)
            .await?;
        let str_bytes = self.read_string(true).await?;
        self.on_value_end();
        Ok(str_bytes.get_str(self))
    }

    async fn next_string_reader(&mut self) -> Result<impl Read + '_, ReaderError> {
        self.start_expected_value_type(ValueType::String, false)
            .await?;
        self.is_string_value_reader_active = true;
        Ok(StringValueReader {
            json_reader: self,
            utf8_buf: [0_u8; STRING_VALUE_READER_BUF_SIZE],
            utf8_start_pos: 0,
            utf8_count: 0,
            reached_end: false,
            error: None,
        })
    }

    async fn next_number_as_string(&mut self) -> Result<String, ReaderError> {
        self.read_number_bytes(false)
            .await
            .map(|b| b.get_string(self))
    }

    async fn next_number_as_str(&mut self) -> Result<&str, ReaderError> {
        self.read_number_bytes(true).await.map(|b| b.get_str(self))
    }

    async fn skip_to_top_level(&mut self) -> Result<(), ReaderError> {
        if self.is_string_value_reader_active {
            panic!("Incorrect reader usage: Cannot skip to top-level when string value reader is active");
        }

        // Handle expected member value separately because has_next() calls below are not allowed when
        // member value is expected
        if self.expects_member_value() {
            self.skip_value().await?;
        }

        while let Some(value_type) = self.stack.last() {
            match value_type {
                StackValue::Array => {
                    while self.has_next().await? {
                        self.skip_value().await?;
                    }
                    self.end_array().await?;
                }
                StackValue::Object => {
                    while self.has_next().await? {
                        self.skip_name().await?;
                        self.skip_value().await?;
                    }
                    self.end_object().await?;
                }
            }
        }
        Ok(())
    }

    async fn consume_trailing_whitespace(mut self) -> Result<(), ReaderError> {
        if self.is_string_value_reader_active {
            panic!("Incorrect reader usage: Cannot consume trailing whitespace when string value reader is active");
        }
        if self.stack.is_empty() {
            if self.is_empty {
                panic!("Incorrect reader usage: Cannot skip trailing whitespace when top-level value has not been consumed yet");
            }
        } else {
            panic!("Incorrect reader usage: Cannot skip trailing whitespace when top-level value has not been fully consumed yet");
        }

        let next_byte = self.skip_whitespace(None).await?;
        return if next_byte.is_some() {
            self.create_syntax_value_error(SyntaxErrorKind::TrailingData)
        } else {
            Ok(())
        };
    }

    fn current_position(&self, include_path: bool) -> JsonReaderPosition {
        JsonReaderPosition {
            path: if include_path {
                self.json_path.clone()
            } else {
                None
            },
            line_pos: Some(LinePosition {
                line: self.line,
                column: self.column,
            }),
            data_pos: Some(self.byte_pos),
        }
    }
}

// - 1, since at least one byte was already consumed
const STRING_VALUE_READER_BUF_SIZE: usize = utf8::MAX_BYTES_PER_CHAR - 1;

struct StringValueReader<'j, R: Read> {
    json_reader: &'j mut JsonStreamReader<R>,
    /// Buffer in case multi-byte character is read but caller did not provide large enough buffer
    utf8_buf: [u8; STRING_VALUE_READER_BUF_SIZE],
    /// Start position within [utf8_buf]
    utf8_start_pos: usize,
    /// Number of bytes currently in the [utf8_buf]
    utf8_count: usize,
    reached_end: bool,
    /// The last error which occurred, and which should be returned for every subsequent `read` call
    // `io::Error` does not implement Clone, so this only contains some of its data
    error: Option<(ErrorKind, String)>,
}

impl<R: Read> ErrorType for StringValueReader<'_, R> {
    type Error = IoError;
}

impl<R: Read> StringValueReader<'_, R> {
    async fn read_impl(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        if self.reached_end || buf.is_empty() {
            return Ok(0);
        }
        let mut pos = 0;
        // Check if there are remaining bytes in the UTF-8 buffer which should be served first
        if self.utf8_count > 0 {
            let copy_count = self.utf8_count.min(buf.len());
            buf[..copy_count].copy_from_slice(
                &self.utf8_buf[self.utf8_start_pos..(self.utf8_start_pos + copy_count)],
            );
            pos += copy_count;

            // Check if complete buffer content was copied
            if copy_count == self.utf8_count {
                self.utf8_start_pos = 0;
                self.utf8_count = 0;
            } else {
                self.utf8_start_pos += copy_count;
                self.utf8_count -= copy_count;
            }
        }

        while pos < buf.len() {
            // Can assume that utf8_start_pos is 0 because it should have been drained at the beginning of
            // this `read` method; otherwise if there were still remaining bytes in the UTF-8 buffer, that
            // would indicate that `buf` was too small and is already full, so no iteration of this loop
            // would have run
            debug_assert!(self.utf8_start_pos == 0 && self.utf8_count == 0);
            let result = self
                .json_reader
                .read_string_bytes(&mut |byte| {
                    if pos < buf.len() {
                        buf[pos] = byte;
                        pos += 1;
                    } else {
                        // Due to loop condition at least one byte was written to `buf`, so at most 3 additional bytes
                        // have to be stored in utf8_buf
                        self.utf8_buf[self.utf8_count] = byte;
                        self.utf8_count += 1;
                    }
                })
                .await;
            match result {
                Ok(reached_end) => {
                    if reached_end {
                        self.reached_end = true;
                        self.json_reader.is_string_value_reader_active = false;
                        self.json_reader.on_value_end();
                        break;
                    }
                }
                Err(e) => match e {
                    StringReadingError::SyntaxError(e) => {
                        return Err(IoError {
                            kind: ErrorKind::Other,
                            message: e.to_string(),
                        })
                    }
                    StringReadingError::IoError(e) => {
                        // Note: Could instead also directly return `Err(e.0)`; that would allow user to
                        // inspect IO error, but would on the other hand lose location information
                        return Err(IoError {
                            kind: ErrorKind::Other,
                            message: e.to_string(),
                        });
                    }
                },
            }
        }
        Ok(pos)
    }

    fn check_previous_error(&self) -> Result<(), IoError> {
        match &self.error {
            None => Ok(()),
            // Report as `Other` kind (and with custom message) to avoid caller indefinitely retrying
            // because it considers the original error kind as safe to retry
            Some(e) => Err(IoError {
                kind: ErrorKind::Other,
                message: format!("previous error '{:?}': {}", e.0, e.1.clone()),
            }),
        }
    }
}
impl<R: Read> Read for StringValueReader<'_, R> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        self.check_previous_error()?;

        let result = self.read_impl(buf).await;
        if let Err(e) = &result {
            self.error = Some((e.kind(), e.to_string()));
        }
        result
    }
}

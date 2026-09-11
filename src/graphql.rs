//! Bounded, schema-independent GraphQL executable-document parser for review.
//! This is NOT an authorization resolver or a full schema validator. Parse
//! once from the immutable buffered body; never rewrite the forwarded bytes.
//! Grammar: https://spec.graphql.org/September2025/#sec-Language
use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

const MAX_TOKENS: usize = 8192;
const MAX_DEPTH: usize = 32;
const MAX_FIELDS: usize = 256;
const MAX_EXPANDED_BYTES: usize = 256 * 1024;
type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Value {
    Variable(String),
    MissingVariable(String),
    Int(String),
    Float(String),
    String(String),
    Enum(String),
    Boolean(bool),
    Null,
    List(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    fn format(&self) -> String {
        match self {
            Self::Variable(name) => format!("${name}"),
            Self::MissingVariable(name) => format!("<missing ${name}>"),
            Self::Int(value) | Self::Float(value) | Self::Enum(value) => value.clone(),
            Self::String(value) => serde_json::to_string(value).expect("string"),
            Self::Boolean(value) => value.to_string(),
            Self::Null => "null".into(),
            Self::List(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(Self::format)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Object(values) => format!("{{{}}}", format_args(values)),
        }
    }
    fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    fn member(&self, name: &str) -> Option<&Value> {
        if let Self::Object(values) = self {
            values.get(name)
        } else {
            None
        }
    }
    fn from_json(value: &Json, depth: usize) -> Result<Self> {
        check_depth(depth)?;
        Ok(match value {
            Json::Null => Self::Null,
            Json::Bool(value) => Self::Boolean(*value),
            Json::String(value) => Self::String(value.clone()),
            Json::Number(value) if value.is_i64() || value.is_u64() => Self::Int(value.to_string()),
            Json::Number(value) => Self::Float(value.to_string()),
            Json::Array(values) => Self::List(
                values
                    .iter()
                    .map(|v| Self::from_json(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Json::Object(values) => Self::Object(
                values
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), Self::from_json(v, depth + 1)?)))
                    .collect::<Result<_>>()?,
            ),
        })
    }
}

fn check_depth(depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        Err("GraphQL nesting exceeds the 32-level review limit".into())
    } else {
        Ok(())
    }
}
fn format_args(args: &BTreeMap<String, Value>) -> String {
    args.iter()
        .map(|(name, value)| format!("{name}: {}", value.format()))
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Name(String),
    Number(String),
    String(String),
    Punct(char),
    Spread,
}
#[derive(Clone, Debug)]
struct Located {
    token: Token,
    offset: usize,
}

fn lex(source: &str) -> Result<Vec<Located>> {
    let mut tokens = Vec::new();
    let mut pos = 0;
    let bytes = source.as_bytes();
    while pos < bytes.len() {
        let start = pos;
        match bytes[pos] {
            b' ' | b'\t' | b'\r' | b'\n' | b',' => {
                pos += 1;
                continue;
            }
            b'#' => {
                while pos < bytes.len() && !matches!(bytes[pos], b'\r' | b'\n') {
                    pos += 1;
                }
                continue;
            }
            _ if source[pos..].starts_with('\u{feff}') => {
                pos += 3;
                continue;
            }
            _ => {}
        }
        let token = match bytes[pos] {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                pos += 1;
                while pos < bytes.len()
                    && (bytes[pos].is_ascii_alphanumeric() || bytes[pos] == b'_')
                {
                    pos += 1;
                }
                Token::Name(source[start..pos].into())
            }
            b'-' | b'0'..=b'9' => {
                if bytes[pos] == b'-' {
                    pos += 1;
                }
                if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
                    return Err(format!("expected number at byte {start}"));
                }
                if bytes[pos] == b'0' {
                    pos += 1;
                } else {
                    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                }
                if pos < bytes.len() && bytes[pos] == b'.' {
                    pos += 1;
                    let digits = pos;
                    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                    if digits == pos {
                        return Err(format!("fraction requires digits at byte {pos}"));
                    }
                }
                if pos < bytes.len() && matches!(bytes[pos], b'e' | b'E') {
                    pos += 1;
                    if pos < bytes.len() && matches!(bytes[pos], b'+' | b'-') {
                        pos += 1;
                    }
                    let digits = pos;
                    while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                        pos += 1;
                    }
                    if digits == pos {
                        return Err(format!("exponent requires digits at byte {pos}"));
                    }
                }
                if pos < bytes.len()
                    && (bytes[pos].is_ascii_alphanumeric() || matches!(bytes[pos], b'_' | b'.'))
                {
                    return Err(format!("invalid number boundary at byte {pos}"));
                }
                Token::Number(source[start..pos].into())
            }
            b'"' => Token::String(read_string(source, &mut pos)?),
            b'.' if source[pos..].starts_with("...") => {
                pos += 3;
                Token::Spread
            }
            b'!' | b'$' | b'(' | b')' | b':' | b'=' | b'@' | b'[' | b']' | b'{' | b'}' => {
                pos += 1;
                Token::Punct(bytes[start] as char)
            }
            _ => return Err(format!("unexpected GraphQL token at byte {pos}")),
        };
        tokens.push(Located {
            token,
            offset: start,
        });
        if tokens.len() > MAX_TOKENS {
            return Err("GraphQL document exceeds the 8192-token review limit".into());
        }
    }
    Ok(tokens)
}

fn read_string(source: &str, pos: &mut usize) -> Result<String> {
    let start = *pos;
    let block = source[*pos..].starts_with("\"\"\"");
    *pos += if block { 3 } else { 1 };
    let mut value = String::new();
    while *pos < source.len() {
        if block {
            if source[*pos..].starts_with("\\\"\"\"") {
                value.push_str("\"\"\"");
                *pos += 4;
                continue;
            }
            if source[*pos..].starts_with("\"\"\"") {
                *pos += 3;
                return Ok(normalize_block(&value));
            }
        } else {
            if source.as_bytes()[*pos] == b'"' {
                *pos += 1;
                return Ok(value);
            }
            if source.as_bytes()[*pos] == b'\\' {
                *pos += 1;
                let escape = *source
                    .as_bytes()
                    .get(*pos)
                    .ok_or("unfinished string escape")?;
                *pos += 1;
                value.push(match escape {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{0008}',
                    b'f' => '\u{000c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => read_unicode(source, pos)?,
                    _ => return Err(format!("invalid string escape at byte {}", *pos - 1)),
                });
                continue;
            }
        }
        let character = source[*pos..].chars().next().expect("character boundary");
        if (character as u32) < 0x20 && !(block && matches!(character, '\n' | '\r' | '\t')) {
            return Err(format!("invalid string control character at byte {pos}"));
        }
        value.push(character);
        *pos += character.len_utf8();
    }
    Err(format!("unterminated string at byte {start}"))
}

fn read_unicode(source: &str, pos: &mut usize) -> Result<char> {
    let bytes = source.as_bytes();
    fn hex(bytes: &[u8], pos: &mut usize, count: usize) -> Result<u32> {
        let part = bytes
            .get(*pos..*pos + count)
            .ok_or("unfinished Unicode escape")?;
        if !part.iter().all(u8::is_ascii_hexdigit) {
            return Err("invalid Unicode escape".into());
        }
        let value = u32::from_str_radix(std::str::from_utf8(part).expect("ASCII hex"), 16)
            .map_err(|_| "invalid Unicode escape")?;
        *pos += count;
        Ok(value)
    }
    let scalar = if bytes.get(*pos) == Some(&b'{') {
        *pos += 1;
        let start = *pos;
        while bytes.get(*pos).is_some_and(u8::is_ascii_hexdigit) {
            *pos += 1;
        }
        if *pos == start || *pos - start > 6 || bytes.get(*pos) != Some(&b'}') {
            return Err("invalid braced Unicode escape".into());
        }
        let value =
            u32::from_str_radix(&source[start..*pos], 16).map_err(|_| "invalid Unicode scalar")?;
        *pos += 1;
        value
    } else {
        let first = hex(bytes, pos, 4)?;
        if (0xd800..=0xdbff).contains(&first) {
            if bytes.get(*pos..*pos + 2) != Some(b"\\u") {
                return Err("high surrogate without low surrogate".into());
            }
            *pos += 2;
            let end = *pos + 4;
            let low_text = source.get(*pos..end).ok_or("unfinished surrogate pair")?;
            let low = u32::from_str_radix(low_text, 16).map_err(|_| "invalid low surrogate")?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err("invalid low surrogate".into());
            }
            *pos = end;
            0x10000 + ((first - 0xd800) << 10) + low - 0xdc00
        } else {
            first
        }
    };
    char::from_u32(scalar).ok_or_else(|| "invalid Unicode scalar".into())
}

fn normalize_block(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<_> = normalized.split('\n').collect();
    let indent = lines
        .iter()
        .skip(1)
        .filter(|line| !line.trim_matches([' ', '\t']).is_empty())
        .map(|line| line.chars().take_while(|c| matches!(c, ' ' | '\t')).count())
        .min()
        .unwrap_or(0);
    let mut lines: Vec<_> = lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                (*line).to_owned()
            } else {
                line.chars()
                    .skip(indent.min(line.chars().take_while(|c| matches!(c, ' ' | '\t')).count()))
                    .collect::<String>()
            }
        })
        .collect();
    while lines
        .last()
        .is_some_and(|line| line.trim_matches([' ', '\t']).is_empty())
    {
        lines.pop();
    }
    let first = lines
        .iter()
        .position(|line| !line.trim_matches([' ', '\t']).is_empty())
        .unwrap_or(lines.len());
    lines[first..].join("\n")
}

#[derive(Clone, Debug)]
struct Directive {
    name: String,
    arguments: BTreeMap<String, Value>,
}
#[derive(Clone, Debug)]
enum Selection {
    Field {
        name: String,
        alias: Option<String>,
        arguments: BTreeMap<String, Value>,
        directives: Vec<Directive>,
        selections: Vec<Selection>,
    },
    Spread {
        name: String,
        directives: Vec<Directive>,
    },
    Inline {
        on_type: Option<String>,
        directives: Vec<Directive>,
        selections: Vec<Selection>,
    },
}
#[derive(Clone, Debug)]
struct Variable {
    name: String,
    type_name: String,
    default: Option<Value>,
    directives: Vec<Directive>,
}
#[derive(Clone, Debug)]
struct Operation {
    kind: String,
    name: Option<String>,
    variables: Vec<Variable>,
    directives: Vec<Directive>,
    selections: Vec<Selection>,
}
#[derive(Clone, Debug)]
struct Fragment {
    name: String,
    on_type: String,
    directives: Vec<Directive>,
    selections: Vec<Selection>,
}
struct Document {
    operations: Vec<Operation>,
    fragments: BTreeMap<String, Fragment>,
}
struct Parser {
    tokens: Vec<Located>,
    pos: usize,
}

impl Parser {
    fn error(&self, message: &str) -> String {
        format!(
            "{message} at {}",
            self.tokens
                .get(self.pos)
                .map(|t| format!("byte {}", t.offset))
                .unwrap_or("end of document".into())
        )
    }
    fn at(&self, c: char) -> bool {
        self.tokens
            .get(self.pos)
            .is_some_and(|t| t.token == Token::Punct(c))
    }
    fn eat(&mut self, c: char) -> bool {
        if self.at(c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, c: char) -> Result<()> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(self.error(&format!("expected '{c}'")))
        }
    }
    fn name(&mut self) -> Result<String> {
        match self.tokens.get(self.pos).map(|t| &t.token) {
            Some(Token::Name(value)) => {
                let value = value.clone();
                self.pos += 1;
                Ok(value)
            }
            _ => Err(self.error("expected name")),
        }
    }
    fn named(&self, name: &str) -> bool {
        self.tokens
            .get(self.pos)
            .is_some_and(|t| t.token == Token::Name(name.into()))
    }
    fn document(&mut self) -> Result<Document> {
        let mut operations = Vec::new();
        let mut fragments = BTreeMap::new();
        let mut names = HashSet::new();
        while self.pos < self.tokens.len() {
            if self.at('{') {
                operations.push(Operation {
                    kind: "query".into(),
                    name: None,
                    variables: vec![],
                    directives: vec![],
                    selections: self.selections(0)?,
                });
                continue;
            }
            let kind = self.name()?;
            if kind == "fragment" {
                let name = self.name()?;
                if name == "on" {
                    return Err(self.error("fragment name cannot be 'on'"));
                }
                if self.name()? != "on" {
                    return Err(self.error("fragment requires type condition"));
                }
                let on_type = self.name()?;
                let directives = self.directives(0, false)?;
                let selections = self.selections(0)?;
                if fragments
                    .insert(
                        name.clone(),
                        Fragment {
                            name,
                            on_type,
                            directives,
                            selections,
                        },
                    )
                    .is_some()
                {
                    return Err("duplicate fragment definition".into());
                }
            } else if matches!(kind.as_str(), "query" | "mutation" | "subscription") {
                let name = if matches!(
                    self.tokens.get(self.pos).map(|t| &t.token),
                    Some(Token::Name(_))
                ) {
                    Some(self.name()?)
                } else {
                    None
                };
                if let Some(name) = &name
                    && !names.insert(name.clone())
                {
                    return Err("duplicate operation name".into());
                }
                let variables = self.variables()?;
                let directives = self.directives(0, false)?;
                let selections = self.selections(0)?;
                operations.push(Operation {
                    kind,
                    name,
                    variables,
                    directives,
                    selections,
                });
            } else {
                return Err(self.error("only executable query, mutation, subscription and fragment definitions are supported"));
            }
        }
        if operations.is_empty() {
            return Err("document contains no operation".into());
        }
        if operations.len() > 1 && operations.iter().any(|op| op.name.is_none()) {
            return Err("anonymous operation must be the only operation".into());
        }
        Ok(Document {
            operations,
            fragments,
        })
    }
    fn variables(&mut self) -> Result<Vec<Variable>> {
        let mut variables = Vec::new();
        let mut names = HashSet::new();
        if self.eat('(') {
            while !self.eat(')') {
                self.expect('$')?;
                let name = self.name()?;
                if !names.insert(name.clone()) {
                    return Err("duplicate variable definition".into());
                }
                self.expect(':')?;
                let type_name = self.type_ref(0)?;
                let default = if self.eat('=') {
                    Some(self.value(0, true)?)
                } else {
                    None
                };
                let directives = self.directives(0, true)?;
                variables.push(Variable {
                    name,
                    type_name,
                    default,
                    directives,
                });
            }
            if variables.is_empty() {
                return Err("empty variable definitions".into());
            }
        }
        Ok(variables)
    }
    fn type_ref(&mut self, depth: usize) -> Result<String> {
        check_depth(depth)?;
        let mut value = if self.eat('[') {
            let inner = self.type_ref(depth + 1)?;
            self.expect(']')?;
            format!("[{inner}]")
        } else {
            self.name()?
        };
        if self.eat('!') {
            value.push('!');
        }
        Ok(value)
    }
    fn arguments(&mut self, depth: usize, constant: bool) -> Result<BTreeMap<String, Value>> {
        let mut args = BTreeMap::new();
        if self.eat('(') {
            while !self.eat(')') {
                let name = self.name()?;
                self.expect(':')?;
                let value = self.value(depth + 1, constant)?;
                if args.insert(name, value).is_some() {
                    return Err("duplicate argument".into());
                }
            }
            if args.is_empty() {
                return Err("empty arguments".into());
            }
        }
        Ok(args)
    }
    fn directives(&mut self, depth: usize, constant: bool) -> Result<Vec<Directive>> {
        let mut result = Vec::new();
        while self.eat('@') {
            result.push(Directive {
                name: self.name()?,
                arguments: self.arguments(depth, constant)?,
            });
        }
        Ok(result)
    }
    fn value(&mut self, depth: usize, constant: bool) -> Result<Value> {
        check_depth(depth)?;
        if self.eat('$') {
            if constant {
                return Err("variable references are not allowed in constant values".into());
            }
            return Ok(Value::Variable(self.name()?));
        }
        if self.eat('[') {
            let mut values = Vec::new();
            while !self.eat(']') {
                values.push(self.value(depth + 1, constant)?);
            }
            return Ok(Value::List(values));
        }
        if self.eat('{') {
            let mut values = BTreeMap::new();
            while !self.eat('}') {
                let name = self.name()?;
                self.expect(':')?;
                let value = self.value(depth + 1, constant)?;
                if values.insert(name, value).is_some() {
                    return Err("duplicate input object field".into());
                }
            }
            return Ok(Value::Object(values));
        }
        let token = self
            .tokens
            .get(self.pos)
            .ok_or_else(|| self.error("expected value"))?
            .token
            .clone();
        self.pos += 1;
        Ok(match token {
            Token::String(value) => Value::String(value),
            Token::Number(value) if value.contains(['.', 'e', 'E']) => Value::Float(value),
            Token::Number(value) => Value::Int(value),
            Token::Name(value) => match value.as_str() {
                "true" => Value::Boolean(true),
                "false" => Value::Boolean(false),
                "null" => Value::Null,
                _ => Value::Enum(value),
            },
            _ => return Err(self.error("expected value")),
        })
    }
    fn selections(&mut self, depth: usize) -> Result<Vec<Selection>> {
        check_depth(depth)?;
        self.expect('{')?;
        let mut selections = Vec::new();
        while !self.eat('}') {
            if self
                .tokens
                .get(self.pos)
                .is_some_and(|t| t.token == Token::Spread)
            {
                self.pos += 1;
                if self.named("on") || self.at('@') || self.at('{') {
                    let on_type = if self.named("on") {
                        self.pos += 1;
                        Some(self.name()?)
                    } else {
                        None
                    };
                    let directives = self.directives(depth, false)?;
                    let children = self.selections(depth + 1)?;
                    selections.push(Selection::Inline {
                        on_type,
                        directives,
                        selections: children,
                    });
                } else {
                    let name = self.name()?;
                    let directives = self.directives(depth, false)?;
                    selections.push(Selection::Spread { name, directives });
                }
            } else {
                let first = self.name()?;
                let (name, alias) = if self.eat(':') {
                    (self.name()?, Some(first))
                } else {
                    (first, None)
                };
                let arguments = self.arguments(depth, false)?;
                let directives = self.directives(depth, false)?;
                let children = if self.at('{') {
                    self.selections(depth + 1)?
                } else {
                    vec![]
                };
                selections.push(Selection::Field {
                    name,
                    alias,
                    arguments,
                    directives,
                    selections: children,
                });
            }
        }
        if selections.is_empty() {
            return Err("empty selection set".into());
        }
        Ok(selections)
    }
}

fn directives_text(directives: &[Directive]) -> String {
    directives
        .iter()
        .map(|d| {
            format!(
                " @{}{}",
                d.name,
                if d.arguments.is_empty() {
                    String::new()
                } else {
                    format!("({})", format_args(&d.arguments))
                }
            )
        })
        .collect()
}
fn selections_text(selections: &[Selection], depth: usize, output: &mut String) {
    output.push_str("{\n");
    for selection in selections {
        output.push_str(&"  ".repeat(depth + 1));
        match selection {
            Selection::Field {
                name,
                alias,
                arguments,
                directives,
                selections,
            } => {
                if let Some(alias) = alias {
                    output.push_str(&format!("{alias}: "));
                }
                output.push_str(name);
                if !arguments.is_empty() {
                    output.push_str(&format!("({})", format_args(arguments)));
                }
                output.push_str(&directives_text(directives));
                if !selections.is_empty() {
                    output.push(' ');
                    selections_text(selections, depth + 1, output);
                }
            }
            Selection::Spread { name, directives } => {
                output.push_str(&format!("...{name}{}", directives_text(directives)));
            }
            Selection::Inline {
                on_type,
                directives,
                selections,
            } => {
                output.push_str("...");
                if let Some(on_type) = on_type {
                    output.push_str(&format!(" on {on_type}"));
                }
                output.push_str(&directives_text(directives));
                output.push(' ');
                selections_text(selections, depth + 1, output);
            }
        }
        output.push('\n');
    }
    output.push_str(&"  ".repeat(depth));
    output.push('}');
}
impl Document {
    fn format(&self) -> String {
        let mut output = String::new();
        for operation in &self.operations {
            if !output.is_empty() {
                output.push_str("\n\n");
            }
            output.push_str(&operation.kind);
            if let Some(name) = &operation.name {
                output.push(' ');
                output.push_str(name);
            }
            if !operation.variables.is_empty() {
                output.push('(');
                output.push_str(
                    &operation
                        .variables
                        .iter()
                        .map(|v| {
                            format!(
                                "${}: {}{}{}",
                                v.name,
                                v.type_name,
                                v.default
                                    .as_ref()
                                    .map(|v| format!(" = {}", v.format()))
                                    .unwrap_or_default(),
                                directives_text(&v.directives)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                output.push(')');
            }
            output.push_str(&directives_text(&operation.directives));
            output.push(' ');
            selections_text(&operation.selections, 0, &mut output);
        }
        for fragment in self.fragments.values() {
            output.push_str(&format!(
                "\n\nfragment {} on {}{} ",
                fragment.name,
                fragment.on_type,
                directives_text(&fragment.directives)
            ));
            selections_text(&fragment.selections, 0, &mut output);
        }
        output
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VariableView {
    pub name: String,
    pub declared_type: String,
    pub source: &'static str,
    pub value: Value,
}

/// A syntactic target, never a verified node-to-repository association.
/// The field path and input path are explicit so a later policy resolver can
/// match all operations, not a client-chosen alias or operation name.
#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Target {
    NodeId {
        input_path: String,
        id: String,
        expected_type: &'static str,
    },
    RepositoryNumber {
        owner: String,
        repository: String,
        number: String,
        expected_type: &'static str,
    },
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Condition {
    Directive {
        name: String,
        arguments: BTreeMap<String, Value>,
    },
    Type {
        name: String,
    },
    Fragment {
        name: String,
        on_type: String,
    },
}
impl Condition {
    fn text(&self) -> String {
        match self {
            Self::Directive { name, arguments } => format!(
                "@{}{} (not evaluated)",
                name,
                if arguments.is_empty() {
                    String::new()
                } else {
                    format!("({})", format_args(arguments))
                }
            ),
            Self::Type { name } => format!("on {name} (type condition not verified)"),
            Self::Fragment { name, on_type } => {
                format!("fragment {name} on {on_type} (type condition not verified)")
            }
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct FieldView {
    pub field: String,
    pub response_name: String,
    pub path: Vec<String>,
    pub parent: Option<usize>,
    pub arguments: BTreeMap<String, Value>,
    pub arguments_text: String,
    /// No branch is removed based on attacker-supplied directives/type names.
    pub conditions: Vec<Condition>,
    pub conditions_text: Vec<String>,
    pub action: Option<&'static str>,
    pub target: Option<Target>,
    /// Payload is intentionally separate from the action/target tuple.
    /// Not rendered as Markdown; comment text is arbitrary guest input.
    pub comment_body: Option<String>,
    /// Labeled, resolved inputs for manual PR/review operations. Never used as
    /// an authorization rule: all other/unknown arguments remain visible too.
    pub mutation_inputs: Vec<MutationInput>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MutationInput {
    pub path: String,
    pub label: &'static str,
    pub value: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Analysis {
    pub version: u32,
    pub operation_type: String,
    pub operation_name: Option<String>,
    pub operation_count: usize,
    pub formatted_document: String,
    pub supplied_variables: String,
    pub effective_variables: Vec<VariableView>,
    pub fields: Vec<FieldView>,
    pub warnings: Vec<String>,
    /// Not deserialized from UI data. A strict, reconstructable command,
    /// independent of the advisory field/target summaries above.
    #[serde(skip)]
    pub comment: Option<CommentPlan>,
}

#[derive(Clone, Debug)]
pub struct CommentPlan {
    pub subject_id: String,
    pub body: String,
    client_mutation_id: Option<Json>,
    response: String,
}
impl CommentPlan {
    /// Automatic grants send only this broker-owned mutation with validated
    /// values. Arbitrary guest GraphQL is never forwarded under a pin.
    pub fn request_body(&self) -> Vec<u8> {
        let mut input = serde_json::json!({"subjectId":self.subject_id,"body":self.body});
        if let Some(value) = &self.client_mutation_id {
            input["clientMutationId"] = value.clone();
        }
        serde_json::to_vec(&serde_json::json!({
            "query":format!("mutation FriendzoneComment($input: AddCommentInput!) {{ {} }}",self.response),
            "operationName":"FriendzoneComment", "variables":{"input":input}
        })).expect("validated command JSON")
    }
}

fn comment_plan(
    document: &Document,
    selected: &Operation,
    variables: &BTreeMap<String, Value>,
    supplied: &serde_json::Map<String, Json>,
) -> Option<CommentPlan> {
    if document.operations.len() != 1
        || !document.fragments.is_empty()
        || selected.kind != "mutation"
        || !selected.directives.is_empty()
        || selected.variables.iter().any(|v| !v.directives.is_empty())
        || selected.selections.len() != 1
        || supplied.keys().any(|key| !variables.contains_key(key))
    {
        return None;
    }
    let Selection::Field {
        name,
        alias,
        arguments,
        directives,
        selections,
    } = &selected.selections[0]
    else {
        return None;
    };
    if name != "addComment" || !directives.is_empty() || arguments.len() != 1 {
        return None;
    }
    let mut used = HashSet::new();
    fn resolve(
        value: &Value,
        expected: &str,
        definitions: &[Variable],
        vars: &BTreeMap<String, Value>,
        used: &mut HashSet<String>,
    ) -> Option<Value> {
        if let Value::Variable(name) = value {
            let definition = definitions.iter().find(|v| v.name == *name)?;
            if definition.type_name.trim_end_matches('!') != expected {
                return None;
            }
            used.insert(name.clone());
            return vars.get(name).cloned();
        }
        Some(value.clone())
    }
    let input = resolve(
        arguments.get("input")?,
        "AddCommentInput",
        &selected.variables,
        variables,
        &mut used,
    )?;
    let Value::Object(input) = input else {
        return None;
    };
    if input
        .keys()
        .any(|k| !matches!(k.as_str(), "subjectId" | "body" | "clientMutationId"))
    {
        return None;
    }
    let Value::String(subject_id) = resolve(
        input.get("subjectId")?,
        "ID",
        &selected.variables,
        variables,
        &mut used,
    )?
    else {
        return None;
    };
    let Value::String(body) = resolve(
        input.get("body")?,
        "String",
        &selected.variables,
        variables,
        &mut used,
    )?
    else {
        return None;
    };
    if subject_id.is_empty() || subject_id.len() > 512 || body.trim().is_empty() {
        return None;
    }
    let client_mutation_id = match input.get("clientMutationId") {
        None => None,
        Some(value) => match resolve(value, "String", &selected.variables, variables, &mut used)? {
            Value::String(text) => Some(Json::String(text)),
            Value::Null => Some(Json::Null),
            _ => return None,
        },
    };
    if used.len() != selected.variables.len() {
        return None;
    }
    fn response(selections: &[Selection], parent: &str) -> bool {
        if selections.is_empty() {
            return false;
        }
        let mut names = HashSet::new();
        for selection in selections {
            let Selection::Field {
                name,
                alias,
                arguments,
                directives,
                selections,
            } = selection
            else {
                return false;
            };
            if !arguments.is_empty()
                || !directives.is_empty()
                || !names.insert(alias.as_ref().unwrap_or(name))
            {
                return false;
            }
            let next = match (parent, name.as_str()) {
                ("payload", "subject") => Some("subject"),
                ("payload", "commentEdge") => Some("edge"),
                ("edge", "node") => Some("comment"),
                (_, "__typename")
                | ("payload", "clientMutationId")
                | ("subject", "id")
                | ("comment", "id" | "url" | "body") => None,
                _ => return false,
            };
            if let Some(next) = next {
                if !response(selections, next) {
                    return false;
                }
            } else if !selections.is_empty() {
                return false;
            }
        }
        true
    }
    if !response(selections, "payload") {
        return None;
    }
    let mut response = format!(
        "{}addComment(input: $input) ",
        alias.as_ref().map(|a| format!("{a}: ")).unwrap_or_default()
    );
    selections_text(selections, 0, &mut response);
    Some(CommentPlan {
        subject_id,
        body,
        client_mutation_id,
        response,
    })
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Review {
    Parsed { analysis: Box<Analysis> },
    Unavailable { message: String },
}

/// JSON duplicate keys are ambiguous across upstream parsers. Reject them
/// throughout the envelope/variables rather than silently selecting the last.
struct UniqueJson(Json);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Json::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<UniqueJson, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Json::Number(n)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueJson, E> {
                Ok(UniqueJson(Json::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Json::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<UniqueJson, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, UniqueJson(value))) =
                    map.next_entry::<String, UniqueJson>()?
                {
                    if values.insert(name, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueJson(Json::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
pub fn review(body: &str, content_type: &str) -> Review {
    inspect(body, content_type).1
}

/// One parse/operation-selection authority for policy and the review view.
/// Display expansion limits must not turn a large read into an approval prompt.
#[cfg(test)]
pub fn inspect(body: &str, content_type: &str) -> (bool, Review) {
    inspect_with_limit(body, content_type, crate::review::MAX_BODY)
}

pub fn inspect_with_limit(body: &str, content_type: &str, max_body: usize) -> (bool, Review) {
    let parsed = match parse_request_with_limit(body, content_type, max_body) {
        Ok(parsed) => parsed,
        Err(message) => return (false, Review::Unavailable { message }),
    };
    let read_only = parsed.document.operations[parsed.selected].kind == "query"
        && query_directives_supported(&parsed);
    let review = match analyze_parsed(&parsed) {
        Ok(analysis) => Review::Parsed {
            analysis: Box::new(analysis),
        },
        Err(message) => Review::Unavailable { message },
    };
    (read_only, review)
}

struct ParsedRequest {
    document: Document,
    selected: usize,
    supplied: serde_json::Map<String, Json>,
}

#[cfg(test)]
fn parse_request(body: &str, content_type: &str) -> Result<ParsedRequest> {
    parse_request_with_limit(body, content_type, crate::review::MAX_BODY)
}

fn parse_request_with_limit(
    body: &str,
    content_type: &str,
    max_body: usize,
) -> Result<ParsedRequest> {
    if body.len() > max_body {
        return Err("GraphQL body exceeds the review limit".into());
    }
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let (query, requested, supplied) = if content_type == "application/json" {
        let UniqueJson(json) = serde_json::from_str(body)
            .map_err(|error| format!("invalid or ambiguous GraphQL JSON: {error}"))?;
        let object = json
            .as_object()
            .ok_or("expected one GraphQL JSON object; batching is not supported")?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "query" | "operationName" | "variables"))
        {
            return Err("GraphQL envelope extensions/unknown fields are not supported for structured review".into());
        }
        let query = object
            .get("query")
            .and_then(Json::as_str)
            .ok_or("query must be a string (persisted queries are not supported)")?
            .to_owned();
        let requested = match object.get("operationName") {
            None | Some(Json::Null) => None,
            Some(Json::String(name)) => Some(name.clone()),
            _ => return Err("operationName must be a string or null".into()),
        };
        let supplied = match object.get("variables") {
            None | Some(Json::Null) => serde_json::Map::new(),
            Some(Json::Object(values)) => values.clone(),
            _ => return Err("variables must be an object or null".into()),
        };
        (query, requested, supplied)
    } else if content_type == "application/graphql" {
        (body.into(), None, serde_json::Map::new())
    } else {
        return Err(
            "structured GraphQL review requires application/json or application/graphql".into(),
        );
    };
    let document = Parser {
        tokens: lex(&query)?,
        pos: 0,
    }
    .document()?;
    validate_fragments(&document)?;
    let selected = if let Some(name) = requested {
        document
            .operations
            .iter()
            .position(|op| op.name.as_deref() == Some(name.as_str()))
            .ok_or("operationName does not select an operation")?
    } else if document.operations.len() == 1 {
        0
    } else {
        return Err("multiple operations require operationName; no operation was guessed".into());
    };
    Ok(ParsedRequest {
        document,
        selected,
        supplied,
    })
}

/// GitHub query fields (including introspection) are reads. Unknown directive
/// extensions are not assumed safe. Walk each fragment once, never expand a DAG
/// for admission; @skip/@include cannot change the operation's root type.
fn query_directives_supported(parsed: &ParsedRequest) -> bool {
    fn supported(directives: &[Directive]) -> bool {
        directives.iter().all(|directive| {
            matches!(directive.name.as_str(), "skip" | "include")
                && directive.arguments.len() == 1
                && matches!(
                    directive.arguments.get("if"),
                    Some(Value::Boolean(_) | Value::Variable(_))
                )
        })
    }
    let operation = &parsed.document.operations[parsed.selected];
    if !operation.directives.is_empty()
        || operation.variables.iter().any(|v| !v.directives.is_empty())
    {
        return false;
    }
    let mut visited = HashSet::new();
    let mut pending: Vec<_> = operation.selections.iter().collect();
    while let Some(selection) = pending.pop() {
        match selection {
            Selection::Field {
                directives,
                selections,
                ..
            }
            | Selection::Inline {
                directives,
                selections,
                ..
            } => {
                if !supported(directives) {
                    return false;
                }
                pending.extend(selections);
            }
            Selection::Spread { name, directives } => {
                if !supported(directives) {
                    return false;
                }
                if visited.insert(name) {
                    let fragment = &parsed.document.fragments[name];
                    if !fragment.directives.is_empty() {
                        return false;
                    }
                    pending.extend(&fragment.selections);
                }
            }
        }
    }
    true
}

#[cfg(test)]
fn analyze(body: &str, content_type: &str) -> Result<Analysis> {
    analyze_parsed(&parse_request(body, content_type)?)
}

fn analyze_parsed(parsed: &ParsedRequest) -> Result<Analysis> {
    let document = &parsed.document;
    let selected = &document.operations[parsed.selected];
    let supplied = &parsed.supplied;
    let mut warnings=vec!["GitHub queries flow automatically on supported transports. Mutations require one-shot approval unless covered by an explicitly saved narrow comment permission. Parsing is not full GitHub schema validation.".into(),
        "Targets come from request arguments and are unverified. Opaque node IDs are not issue/PR numbers; no GitHub lookup has run.".into(),
        "The target hint identifies a primary subject only. Other arguments may change permissions, reference other objects, or perform additional effects; a future rule must constrain the entire operation.".into(),
        "Formatting removes comments and normalizes whitespace/string escapes. The exact original body below remains the approval identity.".into()];
    if document.operations.len() > 1 {
        warnings.push("Only the selected operation is expanded below; the complete document includes other operations.".into());
    }
    let mut variables = BTreeMap::new();
    let mut effective_variables = Vec::new();
    for variable in &selected.variables {
        let (source, value) = if let Some(value) = supplied.get(&variable.name) {
            ("supplied", Value::from_json(value, 0)?)
        } else if let Some(value) = &variable.default {
            ("default", value.clone())
        } else {
            ("missing", Value::MissingVariable(variable.name.clone()))
        };
        if variable.type_name.ends_with('!')
            && matches!(value, Value::MissingVariable(_) | Value::Null)
        {
            return Err(format!(
                "required variable ${} is missing or null",
                variable.name
            ));
        }
        if source == "missing" {
            warnings.push(format!(
                "Optional variable ${} is omitted, not null; schema defaults are unknown.",
                variable.name
            ));
        }
        variables.insert(variable.name.clone(), value.clone());
        effective_variables.push(VariableView {
            name: variable.name.clone(),
            declared_type: variable.type_name.clone(),
            source,
            value,
        });
    }
    if supplied.keys().any(|name| !variables.contains_key(name)) {
        warnings.push("Supplied variables include names not declared by the selected operation. They are not used to infer targets.".into());
    }
    let mut expander = Expander {
        document,
        variables: &variables,
        operation_type: &selected.kind,
        fields: Vec::new(),
        remaining: MAX_EXPANDED_BYTES,
        steps: 0,
    };
    let conditions = expander.conditions(&selected.directives, &[])?;
    expander.expand(&selected.selections, None, &[], &conditions, 0)?;
    Ok(Analysis {
        version: 1,
        operation_type: selected.kind.clone(),
        operation_name: selected.name.clone(),
        operation_count: document.operations.len(),
        formatted_document: document.format(),
        supplied_variables: serde_json::to_string_pretty(&supplied).expect("JSON"),
        effective_variables,
        fields: expander.fields,
        warnings,
        comment: comment_plan(document, selected, &variables, supplied),
    })
}

fn validate_fragments(document: &Document) -> Result<()> {
    // Validate references/cycles even in unselected operations and unused
    // fragments, without expanding the potentially exponential fragment DAG.
    fn collect(selections: &[Selection], output: &mut HashSet<String>) {
        for selection in selections {
            match selection {
                Selection::Spread { name, .. } => {
                    output.insert(name.clone());
                }
                Selection::Field { selections, .. } | Selection::Inline { selections, .. } => {
                    collect(selections, output)
                }
            }
        }
    }
    let mut edges = BTreeMap::new();
    for (name, fragment) in &document.fragments {
        let mut refs = HashSet::new();
        collect(&fragment.selections, &mut refs);
        edges.insert(name.clone(), refs);
    }
    let mut all_refs = HashSet::new();
    for operation in &document.operations {
        collect(&operation.selections, &mut all_refs);
    }
    for refs in edges.values() {
        all_refs.extend(refs.iter().cloned());
    }
    if all_refs
        .iter()
        .any(|name| !document.fragments.contains_key(name))
    {
        return Err("undefined fragment reference".into());
    }
    fn visit(
        name: &str,
        edges: &BTreeMap<String, HashSet<String>>,
        active: &mut HashSet<String>,
        done: &mut HashSet<String>,
        depth: usize,
    ) -> Result<()> {
        check_depth(depth)?;
        if done.contains(name) {
            return Ok(());
        }
        if !active.insert(name.into()) {
            return Err("fragment cycle is not reviewable".into());
        }
        for child in &edges[name] {
            visit(child, edges, active, done, depth + 1)?;
        }
        active.remove(name);
        done.insert(name.into());
        Ok(())
    }
    let mut done = HashSet::new();
    for name in edges.keys() {
        visit(name, &edges, &mut HashSet::new(), &mut done, 0)?;
    }
    Ok(())
}

struct Expander<'a> {
    document: &'a Document,
    variables: &'a BTreeMap<String, Value>,
    operation_type: &'a str,
    fields: Vec<FieldView>,
    remaining: usize,
    steps: usize,
}
impl Expander<'_> {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or("expanded GraphQL exceeds the 256 KiB review budget")?;
        Ok(())
    }
    fn resolve(&mut self, value: &Value, depth: usize) -> Result<Value> {
        check_depth(depth)?;
        self.charge(16)?;
        Ok(match value {
            Value::Variable(name) => {
                let value = self
                    .variables
                    .get(name)
                    .ok_or_else(|| format!("undefined variable ${name}"))?;
                self.resolve(value, depth + 1)?
            }
            Value::List(values) => Value::List(
                values
                    .iter()
                    .map(|v| self.resolve(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(k, v)| {
                        self.charge(k.len())?;
                        Ok((k.clone(), self.resolve(v, depth + 1)?))
                    })
                    .collect::<Result<_>>()?,
            ),
            _ => {
                self.charge(value.format().len())?;
                value.clone()
            }
        })
    }
    fn arguments(&mut self, args: &BTreeMap<String, Value>) -> Result<BTreeMap<String, Value>> {
        args.iter()
            .map(|(k, v)| {
                self.charge(k.len())?;
                Ok((k.clone(), self.resolve(v, 0)?))
            })
            .collect()
    }
    fn conditions(
        &mut self,
        directives: &[Directive],
        parent: &[Condition],
    ) -> Result<Vec<Condition>> {
        let mut conditions = parent.to_vec();
        for directive in directives {
            let args = self.arguments(&directive.arguments)?;
            let value = Condition::Directive {
                name: directive.name.clone(),
                arguments: args,
            };
            self.charge(value.text().len())?;
            conditions.push(value);
        }
        Ok(conditions)
    }
    fn expand(
        &mut self,
        selections: &[Selection],
        parent: Option<usize>,
        path: &[String],
        conditions: &[Condition],
        depth: usize,
    ) -> Result<()> {
        check_depth(depth)?;
        for selection in selections {
            self.steps += 1;
            if self.steps > 1024 {
                return Err("expanded GraphQL exceeds the 1024-selection review limit".into());
            }
            match selection {
                Selection::Field {
                    name,
                    alias,
                    arguments,
                    directives,
                    selections,
                } => {
                    if self.fields.len() >= MAX_FIELDS {
                        return Err("expanded GraphQL exceeds the 256-field review limit".into());
                    }
                    let arguments = self.arguments(arguments)?;
                    let conditions = self.conditions(directives, conditions)?;
                    let mut field_path = path.to_vec();
                    field_path.push(alias.as_ref().unwrap_or(name).clone());
                    let (action, target) = target_for(
                        self.operation_type,
                        name,
                        &arguments,
                        parent.map(|index| &self.fields[index]),
                    );
                    let comment_body = if action == Some("Post comment")
                        || (parent.is_none()
                            && self.operation_type == "mutation"
                            && matches!(
                                name.as_str(),
                                "addPullRequestReview"
                                    | "addPullRequestReviewComment"
                                    | "addPullRequestReviewThread"
                                    | "addPullRequestReviewThreadReply"
                                    | "submitPullRequestReview"
                            )) {
                        arguments
                            .get("input")
                            .and_then(|v| v.member("body"))
                            .and_then(Value::string)
                            .map(str::to_owned)
                    } else {
                        None
                    };
                    let view = FieldView {
                        field: name.clone(),
                        response_name: alias.as_ref().unwrap_or(name).clone(),
                        path: field_path.clone(),
                        parent,
                        arguments_text: format_args(&arguments),
                        mutation_inputs: if parent.is_none() && self.operation_type == "mutation" {
                            mutation_inputs(name, &arguments)
                        } else {
                            vec![]
                        },
                        arguments,
                        conditions: conditions.clone(),
                        conditions_text: conditions.iter().map(Condition::text).collect(),
                        action,
                        target,
                        comment_body,
                    };
                    self.charge(serde_json::to_vec(&view).expect("field").len())?;
                    let index = self.fields.len();
                    self.fields.push(view);
                    self.expand(selections, Some(index), &field_path, &conditions, depth + 1)?;
                }
                Selection::Inline {
                    on_type,
                    directives,
                    selections,
                } => {
                    let mut conditions = self.conditions(directives, conditions)?;
                    if let Some(on_type) = on_type {
                        conditions.push(Condition::Type {
                            name: on_type.clone(),
                        });
                    }
                    self.expand(selections, parent, path, &conditions, depth + 1)?;
                }
                Selection::Spread { name, directives } => {
                    // validate_fragments has checked the full DAG for cycles.
                    let fragment = &self.document.fragments[name];
                    let conditions = self.conditions(directives, conditions)?;
                    let mut conditions = self.conditions(&fragment.directives, &conditions)?;
                    conditions.push(Condition::Fragment {
                        name: name.clone(),
                        on_type: fragment.on_type.clone(),
                    });
                    self.expand(&fragment.selections, parent, path, &conditions, depth + 1)?;
                }
            }
        }
        Ok(())
    }
}

fn target_for(
    kind: &str,
    field: &str,
    args: &BTreeMap<String, Value>,
    parent: Option<&FieldView>,
) -> (Option<&'static str>, Option<Target>) {
    // Explicit schema paths only. Never recursively search for an arbitrary
    // "number"/"subjectId" in body text, aliases, response selections or vars.
    // https://docs.github.com/en/graphql/reference/issues#addcommentinput
    // https://docs.github.com/en/graphql/reference/pulls#addpullrequestreviewinput
    // https://docs.github.com/en/graphql/reference/repos#repository
    let rule = if kind == "mutation" && parent.is_none() {
        match field {
            "addComment" => Some(("Post comment", "subjectId", "Issue or PullRequest")),
            "updateIssue" => Some(("Update issue", "id", "Issue")),
            "closeIssue" => Some(("Close issue", "issueId", "Issue")),
            "reopenIssue" => Some(("Reopen issue", "issueId", "Issue")),
            "addPullRequestReview" => {
                Some(("Add pull request review", "pullRequestId", "PullRequest"))
            }
            "updatePullRequest" => Some(("Update pull request", "pullRequestId", "PullRequest")),
            "createPullRequest" => Some(("Create pull request", "repositoryId", "Repository")),
            "addPullRequestReviewComment"
            | "addPullRequestReviewThread"
            | "submitPullRequestReview" => {
                let input = args.get("input");
                let candidates = [
                    ("pullRequestId", "PullRequest"),
                    ("pullRequestReviewId", "PullRequestReview"),
                    ("inReplyTo", "PullRequestReviewComment"),
                ];
                let provided: Vec<_> = candidates
                    .into_iter()
                    .filter(|(key, _)| {
                        input
                            .and_then(|input| input.member(key))
                            .is_some_and(|v| !matches!(v, Value::Null))
                    })
                    .collect();
                let action = match field {
                    "submitPullRequestReview" => "Submit pull request review",
                    "addPullRequestReviewThread" => "Post review thread",
                    _ => "Post review comment (legacy API)",
                };
                // A request may provide both PR and review/reply IDs. Do not
                // guess which is authoritative; show all exact inputs below.
                if provided.len() == 1 {
                    Some((action, provided[0].0, provided[0].1))
                } else {
                    return (Some(action), None);
                }
            }
            "addPullRequestReviewThreadReply" => Some((
                "Reply to review thread",
                "pullRequestReviewThreadId",
                "PullRequestReviewThread",
            )),
            _ => None,
        }
    } else {
        None
    };
    if let Some((action, key, expected_type)) = rule {
        let target = args
            .get("input")
            .and_then(|v| v.member(key))
            .and_then(Value::string)
            .filter(|v| !v.is_empty())
            .map(|id| Target::NodeId {
                input_path: format!("input.{key}"),
                id: id.into(),
                expected_type,
            });
        return (Some(action), target);
    }
    if kind == "query" && parent.is_none() && field == "node" {
        return (
            None,
            args.get("id")
                .and_then(Value::string)
                .filter(|v| !v.is_empty())
                .map(|id| Target::NodeId {
                    input_path: "id".into(),
                    id: id.into(),
                    expected_type: "Node (unknown type)",
                }),
        );
    }
    if kind == "query"
        && let Some(repository) = parent
        && repository.parent.is_none()
        && repository.field == "repository"
    {
        let expected_type = match field {
            "issue" => "Issue",
            "pullRequest" => "PullRequest",
            "issueOrPullRequest" => "Issue or PullRequest",
            _ => return (None, None),
        };
        if let (Some(owner), Some(repo), Some(Value::Int(number))) = (
            repository.arguments.get("owner").and_then(Value::string),
            repository.arguments.get("name").and_then(Value::string),
            args.get("number"),
        ) && !owner.is_empty()
            && !repo.is_empty()
            && number.parse::<i32>().is_ok_and(|n| n > 0)
        {
            return (
                None,
                Some(Target::RepositoryNumber {
                    owner: owner.into(),
                    repository: repo.into(),
                    number: number.clone(),
                    expected_type,
                }),
            );
        }
    }
    (None, None)
}

fn mutation_inputs(field: &str, args: &BTreeMap<String, Value>) -> Vec<MutationInput> {
    if !matches!(
        field,
        "createPullRequest"
            | "addPullRequestReview"
            | "addPullRequestReviewComment"
            | "addPullRequestReviewThread"
            | "addPullRequestReviewThreadReply"
            | "submitPullRequestReview"
    ) {
        return vec![];
    }
    let Some(Value::Object(input)) = args.get("input") else {
        return vec![];
    };
    input
        .iter()
        .map(|(key, value)| MutationInput {
            path: format!("input.{key}"),
            label: match key.as_str() {
                "repositoryId" => "Destination repository node ID",
                "headRepositoryId" => "Source repository node ID",
                "headRefName" => "Head branch (source)",
                "baseRefName" => "Base branch (destination)",
                "title" => "PR title",
                "body" => "Body text (literal, not Markdown)",
                "draft" => "Draft PR",
                "maintainerCanModify" => "Allow maintainer modifications",
                "event" => "Review event (APPROVE / REQUEST_CHANGES / COMMENT)",
                "pullRequestId" => "Pull request node ID",
                "pullRequestReviewId" => "Review node ID",
                "pullRequestReviewThreadId" => "Review thread node ID",
                "inReplyTo" => "Reply-to comment node ID",
                "commitOID" => "Commit SHA",
                "path" => "File path",
                "line" => "Line / end line",
                "startLine" => "Start line",
                "side" => "Diff side / end side",
                "startSide" => "Start diff side",
                "subjectType" => "Line or file target",
                "position" => "Legacy diff position",
                "threads" => "Review threads",
                "comments" => "Legacy review comments",
                "clientMutationId" => "Client mutation ID",
                _ => "Additional input (inspect before approving)",
            },
            value: value.format(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_classification_uses_selected_operation_not_names_strings_or_display_limits() {
        let classify = |query: &str, operation: Option<&str>| {
            inspect(
                &json!({"query":query,"operationName":operation}).to_string(),
                "application/json",
            )
            .0
        };
        for query in [
            "{ viewer { login } }",
            "query mutation { createPullRequest: viewer { login } }",
            "# mutation { evil }\nquery Q { search(query: \"mutation { addComment }\", type: ISSUE) { issueCount } }",
            "query($skip:Boolean=false){...F} fragment F on Query { viewer @skip(if:$skip) { ... on User { login @include(if:true) } } }",
            "query IntrospectionQuery { __schema { queryType { name } types { kind name fields { name } } } }",
        ] {
            assert!(classify(query, None), "{query}");
        }
        let mixed = "query Read { viewer { id } } mutation Write { createPullRequest(input:{}) { clientMutationId } }";
        assert!(classify(mixed, Some("Read")));
        assert!(!classify(mixed, Some("Write")));
        assert!(!classify(mixed, None));
        assert!(!classify(mixed, Some("missing")));
        for query in [
            "mutation Read { viewer { id } }",
            "subscription Read { viewer { id } }",
            "query Read { viewer { id } } mutation Read { a }",
            "{ ...Missing }",
            "{ ...F } fragment F on Query { ...F }",
            "query @custom { a }",
            "{ a @custom }",
            "{...F} fragment F on Query @custom { a }",
            "query($v:String @custom){a}",
        ] {
            assert!(!classify(query, None), "{query}");
        }
        let huge = format!("query Big {{ {} }}", "viewer { id } ".repeat(300));
        let (read, view) = inspect(&json!({"query":huge}).to_string(), "application/json");
        assert!(read);
        assert!(
            matches!(view, Review::Unavailable { .. }),
            "display budget does not decide operation kind"
        );
        for body in [
            r#"[{"query":"{a}"}]"#,
            r#"{"query":"{a}","query":"mutation{b}"}"#,
            r#"{"query":"{a}","extensions":{}}"#,
            r#"{"query":"{a}","operationName":true}"#,
            r#"{"query":"{a}","variables":[]}"#,
            r#"{"query":"{a}","variables":{"x":1,"x":2}}"#,
        ] {
            assert!(!inspect(body, "application/json").0, "{body}");
        }
        assert!(inspect("query { viewer { login } }", "application/graphql").0);
        assert!(!inspect("query { viewer { login } }", "text/plain").0);
    }

    #[test]
    fn pr_creation_and_review_fixture_inputs_are_manual_only_with_clear_labels() {
        let fixtures: Json =
            serde_json::from_str(include_str!("../tests/fixtures/github_mutations.json")).unwrap();
        for fixture in fixtures.as_array().unwrap() {
            let (read, view) = inspect(&fixture["body"].to_string(), "application/json");
            assert!(!read);
            let Review::Parsed { analysis } = view else {
                panic!("fixture must parse: {fixture}")
            };
            assert!(
                analysis.comment.is_none(),
                "comment grants never cover PR/review mutations"
            );
            let root = &analysis.fields[0];
            assert_eq!(root.action, fixture["action"].as_str());
            assert_eq!(root.field, fixture["field"].as_str().unwrap());
            let Some(Target::NodeId {
                input_path,
                expected_type,
                ..
            }) = &root.target
            else {
                panic!("fixture target")
            };
            assert_eq!(input_path, fixture["target_path"].as_str().unwrap());
            assert_eq!(*expected_type, fixture["target_type"].as_str().unwrap());
            assert!(
                root.mutation_inputs
                    .iter()
                    .any(|input| input.path == fixture["highlight"].as_str().unwrap())
            );
        }
        let analysis=parse("mutation{addPullRequestReviewThread(input:{pullRequestId:\"pr\",pullRequestReviewId:\"review\",body:\"text\"}){thread{id}}}",Json::Null,None).unwrap();
        assert!(
            analysis.fields[0].target.is_none(),
            "do not hide ambiguous target inputs"
        );
        assert_eq!(analysis.fields[0].mutation_inputs.len(), 3);
    }

    #[test]
    fn comment_command_is_reconstructed_from_a_closed_shape_not_arbitrary_graphql() {
        let source = r#"mutation GuestName($target:ID!, $text:String!){alias:addComment(input:{subjectId:$target,body:$text,clientMutationId:null}){commentEdge{node{id url body}}subject{id}clientMutationId}}"#;
        let analysis = parse(
            source,
            json!({"target":"opaque","text":"arbitrary \" mutation { deleteIssue } text"}),
            None,
        )
        .unwrap();
        let plan = analysis.comment.unwrap();
        let body: Json = serde_json::from_slice(&plan.request_body()).unwrap();
        assert_eq!(body["operationName"], "FriendzoneComment");
        assert_eq!(body["variables"]["input"]["subjectId"], "opaque");
        assert_eq!(
            body["variables"]["input"]["body"],
            "arbitrary \" mutation { deleteIssue } text"
        );
        assert!(!body["query"].as_str().unwrap().contains("deleteIssue"));
        assert!(
            body["query"]
                .as_str()
                .unwrap()
                .contains("alias: addComment")
        );
        assert!(
            analyze(
                &String::from_utf8(plan.request_body()).unwrap(),
                "application/json"
            )
            .unwrap()
            .comment
            .is_some()
        );
        let whole = parse(
            "mutation($input:AddCommentInput!){addComment(input:$input){clientMutationId}}",
            json!({"input":{"subjectId":"opaque","body":"hello"}}),
            None,
        )
        .unwrap();
        assert!(whole.comment.is_some());
        for source in [
            "mutation{addComment(input:{subjectId:\"x\",body:\"y\"}){clientMutationId} closeIssue(input:{issueId:\"x\"}){clientMutationId}}",
            "mutation{addComment(input:{subjectId:\"x\",body:\"y\",unknown:true}){clientMutationId}}",
            "mutation{addComment(input:{subjectId:\"x\",body:\"y\"}) @skip(if:false){clientMutationId}}",
            "mutation{...F} fragment F on Mutation{addComment(input:{subjectId:\"x\",body:\"y\"}){clientMutationId}}",
            "mutation{addComment(input:{subjectId:\"x\",body:\"y\"}){subject{secret}}}",
            "mutation{addComment(input:{subjectId:\"x\",body:\"y\"}){x:clientMutationId x:subject{id}}}",
            "mutation($id:String!){addComment(input:{subjectId:$id,body:\"y\"}){clientMutationId}}",
            "mutation($unused:String){addComment(input:{subjectId:\"x\",body:\"y\"}){clientMutationId}}",
            "query{viewer{login}}",
        ] {
            let variables = if source.contains("$id:String!") {
                json!({"id":"x"})
            } else {
                Json::Null
            };
            let analysis = parse(source, variables, None).unwrap();
            assert!(analysis.comment.is_none(), "{source}");
        }
    }
    fn parse(query: &str, variables: Json, operation: Option<&str>) -> Result<Analysis> {
        analyze(
            &json!({"query":query,"variables":variables,"operationName":operation}).to_string(),
            "application/json",
        )
    }

    #[test]
    fn comment_action_target_and_payload_are_independent_of_names_aliases_and_text() {
        let query = r#"mutation NiceName($input: AddCommentInput!) { harmless: addComment(input: $input) { clientMutationId } }"#;
        let first = parse(
            query,
            json!({"input":{"subjectId":"opaque-node","body":"First comment #123"}}),
            None,
        )
        .unwrap();
        let second = parse(
            query,
            json!({"input":{"subjectId":"opaque-node","body":"Entirely different text"}}),
            None,
        )
        .unwrap();
        let field = &first.fields[0];
        assert_eq!(first.operation_type, "mutation");
        assert_eq!(first.operation_name.as_deref(), Some("NiceName"));
        assert_eq!(field.field, "addComment");
        assert_eq!(field.response_name, "harmless");
        assert_eq!(field.action, Some("Post comment"));
        assert_eq!(field.target, second.fields[0].target);
        assert_eq!(
            field.target,
            Some(Target::NodeId {
                input_path: "input.subjectId".into(),
                id: "opaque-node".into(),
                expected_type: "Issue or PullRequest"
            })
        );
        assert_eq!(field.comment_body.as_deref(), Some("First comment #123"));
        assert_ne!(field.arguments, second.fields[0].arguments);
        assert!(first.fields[1].target.is_none());
        assert_eq!(first.fields[1].parent, Some(0));
        let changed = parse(
            query,
            json!({"input":{"subjectId":"other-node","body":"First comment #123"}}),
            None,
        )
        .unwrap();
        assert_ne!(field.target, changed.fields[0].target);
    }

    #[test]
    fn github_primary_targets_preserve_additional_effects_and_never_equate_reviews_with_comments() {
        let analysis=parse(r#"mutation($input: AddPullRequestReviewInput!) {
            review: addPullRequestReview(input: $input) { clientMutationId }
            updateIssue(input: {id: "issue", title: "changed", labelIds: ["other-object"]}) { clientMutationId }
            updatePullRequest(input: {pullRequestId: "pr", baseRefName: "different-branch"}) { clientMutationId }
            reopenIssue(input: {issueId: "issue"}) { clientMutationId }
        }"#,json!({"input":{"pullRequestId":"pr","event":"APPROVE","threads":[{"path":"code.rs","body":"line comment","line":4}]}}),None).unwrap();
        let fields: Vec<_> = analysis
            .fields
            .iter()
            .filter(|field| field.parent.is_none())
            .collect();
        assert_eq!(fields[0].action, Some("Add pull request review"));
        assert!(fields[0].comment_body.is_none());
        assert_eq!(
            fields[0].arguments["input"]
                .member("event")
                .and_then(Value::string),
            Some("APPROVE")
        );
        assert!(fields.iter().all(|field| field.target.is_some()));
        assert!(fields[1].arguments["input"].member("labelIds").is_some());
        assert!(fields[2].arguments["input"].member("baseRefName").is_some());
        assert_eq!(fields[3].action, Some("Reopen issue"));
        let query=parse(r#"{ a: repository(owner: "one",name:"repo") { issue(number:1) { id } } b: repository(owner:"two",name:"repo") { issueOrPullRequest(number:1) { id } } }"#,Json::Null,None).unwrap();
        let targets: Vec<_> = query
            .fields
            .iter()
            .filter_map(|field| field.target.as_ref())
            .collect();
        assert_eq!(targets.len(), 2);
        assert_ne!(targets[0], targets[1]);
    }

    #[test]
    fn literal_default_input_and_variable_object_resolve_to_same_target_and_arguments() {
        let inline=parse(r#"mutation { addComment(input:{subjectId:"same",body:"hello"}) { clientMutationId } }"#,Json::Null,None).unwrap();
        let default=parse(r#"mutation($i:AddCommentInput!={subjectId:"same",body:"hello"}) { addComment(input:$i) { clientMutationId } }"#,Json::Null,None).unwrap();
        let supplied = parse(
            r#"mutation($i:AddCommentInput!) { addComment(input:$i) { clientMutationId } }"#,
            json!({"i":{"subjectId":"same","body":"hello"}}),
            None,
        )
        .unwrap();
        assert_eq!(inline.fields[0].arguments, default.fields[0].arguments);
        assert_eq!(inline.fields[0].arguments, supplied.fields[0].arguments);
        assert_eq!(inline.fields[0].target, supplied.fields[0].target);
    }

    #[test]
    fn deterministic_hostile_token_corpus_never_panics_or_loses_consumed_input() {
        let alphabet = [
            '{', '}', '[', ']', '(', ')', ':', '$', '@', '!', '=', '.', ',', 'a', '0', '1', '-',
            'e', '"', '\\', '\n', 'é', '🚀', '\u{feff}',
        ];
        let mut seed = 0x1234_5678_u64;
        for iteration in 0..4000 {
            let mut input = String::new();
            for _ in 0..(iteration % 128) {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                input.push(alphabet[(seed >> 32) as usize % alphabet.len()]);
            }
            if let Ok(analysis) = analyze(&input, "application/graphql") {
                let again = analyze(&analysis.formatted_document, "application/graphql")
                    .expect("formatted parsed syntax remains parseable");
                assert_eq!(analysis.operation_type, again.operation_type);
                assert_eq!(analysis.fields.len(), again.fields.len());
            }
        }
    }

    #[test]
    fn operation_selection_is_exact_and_every_root_field_is_retained() {
        let query = r#"query Read { viewer { login } } mutation Write { x: addComment(input: {subjectId: "one", body: "text"}) { clientMutationId } y: closeIssue(input: {issueId: "two"}) { clientMutationId } }"#;
        assert!(
            parse(query, Json::Null, None)
                .unwrap_err()
                .contains("operationName")
        );
        assert!(parse(query, Json::Null, Some("missing")).is_err());
        let selected = parse(query, Json::Null, Some("Write")).unwrap();
        assert_eq!(selected.operation_type, "mutation");
        assert_eq!(selected.operation_count, 2);
        assert_eq!(
            selected
                .fields
                .iter()
                .filter(|f| f.parent.is_none())
                .map(|f| f.field.as_str())
                .collect::<Vec<_>>(),
            vec!["addComment", "closeIssue"]
        );
        let read = parse(query, Json::Null, Some("Read")).unwrap();
        assert_eq!(read.fields[0].field, "viewer");
        assert!(read.formatted_document.contains("mutation Write"));
        for invalid in [
            "{ viewer { login } } query Another { viewer { id } }",
            "query Same { a } mutation Same { b }",
            "fragment X on Query { a }",
            "query { a } query Other { b }",
        ] {
            assert!(parse(invalid, Json::Null, None).is_err(), "{invalid}");
        }
    }

    #[test]
    fn defaults_null_missing_variables_and_enum_types_remain_distinct() {
        let query = r#"query Q($owner: String! = "cline", $number: Int = 42, $optional: String, $value: String = "fallback") { repository(owner: $owner, name: "cline") { pullRequest(number: $number) { id } } field(value: $value, optional: $optional, state: OPEN, states: [OPEN, CLOSED]) }"#;
        let analysis = parse(query, json!({"value":null}), None).unwrap();
        assert!(
            analysis
                .effective_variables
                .iter()
                .any(|v| v.name == "value" && v.value == Value::Null && v.source == "supplied")
        );
        assert!(
            analysis
                .effective_variables
                .iter()
                .any(|v| v.name == "number" && v.source == "default")
        );
        assert!(
            analysis
                .effective_variables
                .iter()
                .any(|v| v.name == "optional" && matches!(v.value, Value::MissingVariable(_)))
        );
        let field = analysis.fields.iter().find(|f| f.field == "field").unwrap();
        assert_eq!(field.arguments["state"], Value::Enum("OPEN".into()));
        assert!(parse(query, json!({"owner":null}), None).is_err());
        assert!(parse("query($id: ID!) { node(id: $id) { id } }", Json::Null, None).is_err());
        assert!(parse("{ node(id: $undefined) { id } }", Json::Null, None).is_err());
        assert!(
            parse(
                "query($id: ID = $other) { node(id: $id) { id } }",
                Json::Null,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn fragments_and_conditions_are_expanded_without_trusting_or_hiding_branches() {
        let query = r#"query($n: Int = 12, $skip: Boolean = true) { alias: repository(owner: "cline", name: "cline") { ...Target @skip(if: $skip) } } fragment Target on Repository { ... on Repository @include(if: false) { disguised: pullRequest(number: $n) { id } } }"#;
        let analysis = parse(query, Json::Null, None).unwrap();
        let field = analysis
            .fields
            .iter()
            .find(|f| f.field == "pullRequest")
            .unwrap();
        assert_eq!(field.path, vec!["alias", "disguised"]);
        assert!(
            field
                .conditions_text
                .iter()
                .any(|c| c.contains("@skip(if: true)"))
        );
        assert!(
            field
                .conditions_text
                .iter()
                .any(|c| c.contains("@include(if: false)"))
        );
        assert_eq!(
            field.target,
            Some(Target::RepositoryNumber {
                owner: "cline".into(),
                repository: "cline".into(),
                number: "12".into(),
                expected_type: "PullRequest"
            })
        );
        for invalid in [
            "{ ...Missing }",
            "{ ...A } fragment A on Query { ...B } fragment B on Query { ...A }",
            "{ viewer { id } } fragment Unused on Query { ...Unused }",
            "{ ...A } fragment A on Query { a } fragment A on Query { b }",
        ] {
            assert!(parse(invalid, Json::Null, None).is_err(), "{invalid}");
        }
    }

    #[test]
    fn target_paths_never_guess_from_text_response_fields_or_unused_variables() {
        let query = r#"mutation($input: AddCommentInput!) { addComment(input: $input) { repository(owner: "fake", name: "repo") { issue(number: 99) { id } } } }"#;
        let analysis=parse(query,json!({"input":{"body":"Post on #99","unknown":{"subjectId":"wrong"}},"subjectId":"also-wrong","number":99}),None).unwrap();
        assert!(analysis.fields.iter().all(|f| f.target.is_none()));
        let direct = parse(
            "{ node(id: \"PR_opaque_do_not_decode\") { ... on PullRequest { number } } }",
            Json::Null,
            None,
        )
        .unwrap();
        assert_eq!(
            direct.fields[0].target,
            Some(Target::NodeId {
                input_path: "id".into(),
                id: "PR_opaque_do_not_decode".into(),
                expected_type: "Node (unknown type)"
            })
        );
        let nested=parse("{ organization(login: \"x\") { repository(name: \"y\") { pullRequest(number: 5) { id } } } }",Json::Null,None).unwrap();
        assert!(nested.fields.iter().all(|f| f.target.is_none()));
        let aliased = parse(
            "{ repository: viewer { issue(number: 3) { id } } }",
            Json::Null,
            None,
        )
        .unwrap();
        assert!(aliased.fields.iter().all(|f| f.target.is_none()));
    }

    #[test]
    fn lexer_handles_comments_bom_commas_numbers_and_unicode_block_strings() {
        let query = concat!(
            "\u{feff}# mutation Fake { deleteIssue }\n",
            "query Q { field(a: -3, b: 1.25e+2, text: \"\\uD83D\\uDE80\\u{1F600}\\n\\\"\", block: \"\"\"\n",
            "    first line\n",
            "      indented line\n",
            "    escaped \\\"\"\" triple\n",
            "\"\"\") }"
        );
        let analysis = parse(query, Json::Null, None).unwrap();
        let args = &analysis.fields[0].arguments;
        assert_eq!(args["a"], Value::Int("-3".into()));
        assert_eq!(args["b"], Value::Float("1.25e+2".into()));
        assert_eq!(args["text"], Value::String("🚀😀\n\"".into()));
        assert_eq!(
            args["block"],
            Value::String("first line\n  indented line\nescaped \"\"\" triple".into())
        );
        let roundtrip = parse(&analysis.formatted_document, Json::Null, None).unwrap();
        assert_eq!(roundtrip.fields[0].arguments, *args);
        assert_eq!(roundtrip.formatted_document, analysis.formatted_document);
        for literal in [
            "01",
            "1.",
            "1e",
            "1e+",
            "-",
            "1x",
            "\"\\uD800\"",
            "\"\\uDEAD\"",
            "\"\\u{110000}\"",
            "\"unterminated",
            "\"\\x12\"",
        ] {
            assert!(
                parse(&format!("{{ field(value: {literal}) }}"), Json::Null, None).is_err(),
                "{literal}"
            );
        }
    }

    #[test]
    fn ambiguous_envelopes_duplicates_and_unsupported_syntax_never_return_partial_analysis() {
        for body in [
            r#"[{"query":"{a}"}]"#,
            r#"{"query":"{a}","query":"mutation{b}"}"#,
            r#"{"query":"query($v:X){f(v:$v)}","variables":{"v":{"x":1,"x":2}}}"#,
            r#"{"query":"{a}","variables":[]}"#,
            r#"{"query":"{a}","operationName":1}"#,
            r#"{"extensions":{"persistedQuery":{}}}"#,
            r#"{"query":"{a}","extensions":{}}"#,
        ] {
            assert!(
                matches!(review(body, "application/json"), Review::Unavailable { .. }),
                "{body}"
            );
        }
        for query in [
            "{ f(a:1,a:2) }",
            "{ f(input:{x:1,x:2}) }",
            "query($x:Int,$x:String){a}",
            "{}",
            "query(){a}",
            "{f()}",
            "type Query { a: String }",
            "query Q { a } trailing",
            "fragment on on Query { a }",
        ] {
            assert!(parse(query, Json::Null, None).is_err(), "{query}");
        }
        assert!(analyze("{ viewer { login } }", "application/graphql").is_ok());
        assert!(analyze("{ viewer { login } }", "text/plain").is_err());
    }

    #[test]
    fn work_budgets_bound_deep_large_and_exponentially_reused_documents() {
        let deep = format!("{}id{}", "{a".repeat(40), "}".repeat(40));
        assert!(parse(&deep, Json::Null, None).is_err());
        let many = format!("{{ {} }}", "a ".repeat(300));
        assert!(
            parse(&many, Json::Null, None)
                .unwrap_err()
                .contains("field")
        );
        let tokens = format!("{{f(v:[{}])}}", "0 ".repeat(9000));
        assert!(
            parse(&tokens, Json::Null, None)
                .unwrap_err()
                .contains("token")
        );
        let mut query = "{...F0}".to_string();
        for n in 0..15 {
            query.push_str(&format!(
                " fragment F{n} on Query {{ ...F{} ...F{} }}",
                n + 1,
                n + 1
            ));
        }
        query.push_str(" fragment F15 on Query { a }");
        assert!(parse(&query, Json::Null, None).is_err());
        let query = "query($large:String){f(a:$large,b:$large,c:$large,d:$large)}";
        assert!(
            parse(query, json!({"large":"x".repeat(45000)}), None)
                .unwrap_err()
                .contains("budget")
        );
        let result = std::panic::catch_unwind(|| {
            for n in 0..1024 {
                let query = format!("{{f(v: \"\\u{:04x}\")}}", n);
                let _ = parse(&query, Json::Null, None);
            }
        });
        assert!(result.is_ok());
    }
}

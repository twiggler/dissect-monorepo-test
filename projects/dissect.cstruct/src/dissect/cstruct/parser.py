from __future__ import annotations

import ast
import re
<<<<<<< HEAD
from typing import TYPE_CHECKING, Any
=======
from typing import TYPE_CHECKING
>>>>>>> Rewrite lexer and parser

from dissect.cstruct import compiler
from dissect.cstruct.exceptions import (
    ExpressionParserError,
<<<<<<< HEAD
    ExpressionTokenizerError,
    ParserError,
)
from dissect.cstruct.expression import Expression
from dissect.cstruct.types import BaseArray, Field, Structure

if TYPE_CHECKING:
    from dissect.cstruct import cstruct
    from dissect.cstruct.types import BaseType


class Parser:
=======
    ParserError,
)
from dissect.cstruct.expression import Expression
from dissect.cstruct.lexer import _IDENTIFIER_TYPES, TokenCursor, TokenType, tokenize
from dissect.cstruct.types import BaseArray, BaseType, Field, Structure

if TYPE_CHECKING:
    from dissect.cstruct import cstruct
    from dissect.cstruct.lexer import Token
    from dissect.cstruct.types import BaseType, Enum, Flag


class Parser(TokenCursor):
>>>>>>> Rewrite lexer and parser
    """Base class for definition parsers.

    Args:
        cs: An instance of cstruct.
    """

    def __init__(self, cs: cstruct):
<<<<<<< HEAD
        self.cstruct = cs
=======
        super().__init__()
        self.cs = cs
>>>>>>> Rewrite lexer and parser

    def parse(self, data: str) -> None:
        """This function should parse definitions to cstruct types.

        Args:
<<<<<<< HEAD
            data: Data to parse definitions from, usually a string.
=======
            data: Data to parse definitions from.
>>>>>>> Rewrite lexer and parser
        """
        raise NotImplementedError


<<<<<<< HEAD
class TokenParser(Parser):
    """Definition parser for C-like structure syntax.
=======
def _join_line_continuations(string: str) -> str:
    # Join lines ending with backslash
    return re.sub(r"\\\n", "", string)


class CStyleParser(Parser):
    """Recursive descent parser for C-like structure definitions.
>>>>>>> Rewrite lexer and parser

    Args:
        cs: An instance of cstruct.
        compiled: Whether structs should be compiled or not.
<<<<<<< HEAD
=======
        align: Whether to use aligned struct reads.
>>>>>>> Rewrite lexer and parser
    """

    def __init__(self, cs: cstruct, compiled: bool = True, align: bool = False):
        super().__init__(cs)
<<<<<<< HEAD

        self.compiled = compiled
        self.align = align
        self.TOK = self._tokencollection()
        self._conditionals = []
        self._conditionals_depth = 0

    @staticmethod
    def _tokencollection() -> TokenCollection:
        TOK = TokenCollection()
        TOK.add(r"#\[(?P<values>[^\]]+)\](?=\s*)", "CONFIG_FLAG")
        TOK.add(r"#define\s+(?P<name>[^\s]+)(?P<value>[^\r\n]*)", "DEFINE")
        TOK.add(r"#undef\s+(?P<name>[^\s]+)\s*", "UNDEF")
        TOK.add(r"#ifdef\s+(?P<name>[^\s]+)\s*", "IFDEF")
        TOK.add(r"#ifndef\s+(?P<name>[^\s]+)\s*", "IFNDEF")
        TOK.add(r"#else\s*", "ELSE")
        TOK.add(r"#endif\s*", "ENDIF")
        TOK.add(r"typedef(?=\s)", "TYPEDEF")
        TOK.add(r"(?:struct|union)(?=\s|{)", "STRUCT")
        TOK.add(
            r"(?P<enumtype>enum|flag)\s+(?P<name>[^\s:{]+)?\s*(:\s"
            r"*(?P<type>[^{]+?)\s*)?\{(?P<values>[^}]+)\}\s*(?=;)",
            "ENUM",
        )
        TOK.add(r"(?<=})\s*(?P<defs>(?:[a-zA-Z0-9_]+\s*,\s*)+[a-zA-Z0-9_]+)\s*(?=;)", "DEFS")
        TOK.add(r"(?P<name>\**?\s*[a-zA-Z0-9_]+)(?:\s*:\s*(?P<bits>\d+))?(?:\[(?P<count>[^;]*)\])?\s*(?=;)", "NAME")
        TOK.add(r"#include\s+(?P<name>[^\s]+)\s*", "INCLUDE")
        TOK.add(r"[a-zA-Z_][a-zA-Z0-9_]*", "IDENTIFIER")
        TOK.add(r"[{}]", "BLOCK")
        TOK.add(r"\$(?P<name>[^\s]+) = (?P<value>{[^}]+})\w*[\r\n]+", "LOOKUP")
        TOK.add(r";", "EOL")
        TOK.add(r"\s+", None)
        TOK.add(r".", None)

        return TOK

    def _identifier(self, tokens: TokenConsumer) -> str:
        idents = []
        while tokens.next == self.TOK.IDENTIFIER:
            idents.append(tokens.consume())
        return " ".join([i.value for i in idents])

    def _conditional(self, tokens: TokenConsumer) -> None:
        token = tokens.consume()
        pattern = self.TOK.patterns[token.token]
        match = pattern.match(token.value).groupdict()

        value = match["name"]

        if token.token == self.TOK.IFDEF:
            self._conditionals.append(value in self.cstruct.consts)
        elif token.token == self.TOK.IFNDEF:
            self._conditionals.append(value not in self.cstruct.consts)

    def _check_conditional(self, tokens: TokenConsumer) -> bool:
        """Check and handle conditionals. Return a boolean indicating if we need to continue to the next token."""
        if self._conditionals and self._conditionals_depth == len(self._conditionals):
            # If we have a conditional and the depth matches, handle it accordingly
            if tokens.next == self.TOK.ELSE:
                # Flip the last conditional
                tokens.consume()
                self._conditionals[-1] = not self._conditionals[-1]
                return True

            if tokens.next == self.TOK.ENDIF:
                # Pop the last conditional
                tokens.consume()
                self._conditionals.pop()
                self._conditionals_depth -= 1
                return True

        if tokens.next in (self.TOK.IFDEF, self.TOK.IFNDEF):
            # If we encounter a new conditional, increase the depth
            self._conditionals_depth += 1

        if tokens.next == self.TOK.ENDIF:
            # Similarly, decrease the depth if needed
            self._conditionals_depth -= 1

        if self._conditionals and not self._conditionals[-1]:
            # If the last conditional evaluated to False, skip the next token
            tokens.consume()
            return True

        if tokens.next in (self.TOK.IFDEF, self.TOK.IFNDEF):
            # If the next token is a conditional, process it
            self._conditional(tokens)
            return True

        return False

    def _constant(self, tokens: TokenConsumer) -> None:
        const = tokens.consume()
        pattern = self.TOK.patterns[self.TOK.DEFINE]
        match = pattern.match(const.value).groupdict()

        value = match["value"].strip()
        try:
=======
        self.compiled = compiled
        self.align = align

        self._flags: list[str] = []
        self._conditional_stack: list[tuple[Token, bool]] = []

    def reset(self) -> None:
        """Reset the parser state for a new input."""
        self._reset_tokens([])
        self._flags = []
        self._conditional_stack = []

    def parse(self, data: str) -> None:
        """Parse C-like definitions from the input data."""
        self.reset()

        data = _join_line_continuations(data)

        # Tokenize and preprocess the input, then parse top-level definitions
        self._reset_tokens(tokenize(data))
        preprocessed_tokens = self._preprocess()
        self.reset()

        self._reset_tokens(preprocessed_tokens)
        self._parse()

    def _match(self, *types: TokenType) -> Token | None:
        """Consume and return the current token if it matches any of the given types, otherwise return None."""
        if self._current().type in types:
            return self._take()
        return None

    def _at(self, *types: TokenType) -> bool:
        """Return whether the current token matches any of the given types."""
        return self._tokens[self._pos].type in types

    def _at_value(self, value: str) -> bool:
        """Return whether the current token is an identifier with the given value."""
        token = self._tokens[self._pos]
        return token.type == TokenType.IDENTIFIER and token.value == value

    def _error(self, msg: str, *, token: Token | None = None) -> ParserError:
        return ParserError(f"line {(token if token is not None else self._tokens[self._pos]).line}: {msg}")

    def _preprocess(self) -> list[Token]:
        """Handle preprocessor directives and return a new list of tokens with directives processed."""
        result = []

        while self._tokens[self._pos].type != TokenType.EOF:
            token = self._tokens[self._pos]

            # Always handle conditional directives first (even in false branches)
            if token.type in (TokenType.PP_IFDEF, TokenType.PP_IFNDEF, TokenType.PP_ELSE, TokenType.PP_ENDIF):
                self._handle_conditional()
                continue

            # If we're in a false conditional branch, skip this token
            if self._conditional_stack and not self._conditional_stack[-1][1]:
                self._pos += 1
                continue

            if token.type == TokenType.PP_DEFINE:
                self._parse_define()
            elif token.type == TokenType.PP_UNDEF:
                self._parse_undef()
            elif token.type == TokenType.PP_INCLUDE:
                self._parse_include()
            else:
                # Not a preprocessor directive, just add it to the result
                result.append(token)
                self._pos += 1

        # Append EOF token
        result.append(self._tokens[self._pos])
        self._pos += 1

        if self._conditional_stack:
            raise self._error("unclosed conditional statement", token=self._conditional_stack[-1][0])

        return result

    def _parse(self) -> None:
        """Parse top-level definitions from the token stream."""
        while (token := self._current()).type != TokenType.EOF:
            if token.type == TokenType.PP_FLAGS:
                self._parse_config_flags()
            elif token.type == TokenType.LOOKUP:
                self._parse_lookup()
            elif token.type == TokenType.TYPEDEF:
                self._parse_typedef()
            elif token.type in (TokenType.STRUCT, TokenType.UNION):
                self._parse_struct_or_union()

                # Skip variable declarations after struct/union definitions
                while not self._at(TokenType.SEMICOLON, TokenType.EOF):
                    self._pos += 1

                self._expect(TokenType.SEMICOLON)
            elif token.type in (TokenType.ENUM, TokenType.FLAG):
                type_ = self._parse_enum_or_flag()

                # If it's an anonymous enum/flag, add its members to the constants for convenience
                if not type_.__name__:
                    self.cs.consts.update(type_.__members__)

                self._expect(TokenType.SEMICOLON)
            else:
                raise self._error(f"unexpected token {token.value!r}")

    # Preprocessor directives

    def _parse_define(self) -> None:
        """Parse a define directive and add the constant."""
        self._expect(TokenType.PP_DEFINE)

        name_token = self._expect(TokenType.IDENTIFIER)

        # Collect all tokens on the same line as the #define
        parts = []
        while (token := self._current()).type != TokenType.EOF and token.line == name_token.line:
            parts.append(self._take().value)

        value = " ".join(parts).strip()
        try:
            # Lazy mode, try to evaluate as a Python literal first (for simple constants)
>>>>>>> Rewrite lexer and parser
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            pass

<<<<<<< HEAD
        if isinstance(value, str):
            try:
                value = Expression(value).evaluate(self.cstruct)
            except (ExpressionParserError, ExpressionTokenizerError):
                pass

        self.cstruct.consts[match["name"]] = value

    def _undef(self, tokens: TokenConsumer) -> None:
        const = tokens.consume()
        pattern = self.TOK.patterns[self.TOK.UNDEF]
        match = pattern.match(const.value).groupdict()

        if match["name"] in self.cstruct.consts:
            del self.cstruct.consts[match["name"]]
        else:
            raise ParserError(f"line {self._lineno(const)}: constant {match['name']!r} not defined")

    def _enum(self, tokens: TokenConsumer) -> None:
        # We cheat with enums because the entire enum is in the token
        etok = tokens.consume()

        pattern = self.TOK.patterns[self.TOK.ENUM]
        # Dirty trick because the regex expects a ; but we don't want it to be part of the value
        d = pattern.match(etok.value + ";").groupdict()
        enumtype = d["enumtype"]

        nextval = 0
        if enumtype == "flag":
            nextval = 1

        values = {}
        for line in d["values"].splitlines():
            for v in line.split(","):
                key, _, val = v.partition("=")
                key = key.strip()
                val = val.strip()
                if not key:
                    continue

                val = nextval if not val else Expression(val).evaluate(self.cstruct, values)

                if enumtype == "flag":
                    high_bit = val.bit_length() - 1
                    nextval = 2 ** (high_bit + 1)
                else:
                    nextval = val + 1

                values[key] = val

        if not d["type"]:
            d["type"] = "uint32"

        factory = self.cstruct._make_flag if enumtype == "flag" else self.cstruct._make_enum

        enum = factory(d["name"] or "", self.cstruct.resolve(d["type"]), values)
        if not enum.__name__:
            self.cstruct.consts.update(enum.__members__)
        else:
            self.cstruct.add_type(enum.__name__, enum)

        tokens.eol()

    def _typedef(self, tokens: TokenConsumer) -> None:
        tokens.consume()
        type_ = None

        names = []

        if tokens.next == self.TOK.IDENTIFIER:
            type_ = self.cstruct.resolve(self._identifier(tokens))
        elif tokens.next == self.TOK.STRUCT:
            type_ = self._struct(tokens)
            if not type_.__anonymous__:
                names.append(type_.__name__)

        names.extend(self._names(tokens))
        for name in names:
            if issubclass(type_, Structure) and type_.__anonymous__:
                type_.__anonymous__ = False
                type_.__name__ = name
                type_.__qualname__ = name

            type_, name, bits = self._parse_field_type(type_, name)
            if bits is not None:
                raise ParserError(f"line {self._lineno(tokens.previous)}: typedefs cannot have bitfields")
            self.cstruct.add_type(name, type_)

    def _struct(self, tokens: TokenConsumer, register: bool = False) -> type[Structure]:
        stype = tokens.consume()

        factory = self.cstruct._make_union if stype.value.startswith("union") else self.cstruct._make_struct

        st = None
        names = []
        registered = False

        if tokens.next == self.TOK.IDENTIFIER:
            ident = tokens.consume()
            if register:
                # Pre-register an empty struct for self-referencing
                # We update this instance later with the fields
                st = factory(ident.value, [], align=self.align)
                if self.compiled and "nocompile" not in tokens.flags:
                    st = compiler.compile(st)
                self.cstruct.add_type(ident.value, st)
                registered = True
            else:
                names.append(ident.value)

        if tokens.next == self.TOK.NAME:
            # As part of a struct field
            # struct type_name field_name;
            if not names:
                raise ParserError(f"line {self._lineno(tokens.next)}: unexpected anonymous struct")
            return self.cstruct.resolve(names[0])

        if tokens.next != self.TOK.BLOCK:
            raise ParserError(f"line {self._lineno(tokens.next)}: expected start of block '{tokens.next}'")

        fields = []
        tokens.consume()
        while len(tokens):
            if tokens.next == self.TOK.BLOCK and tokens.next.value == "}":
                tokens.consume()
                break

            if self._check_conditional(tokens):
                continue

            field = self._parse_field(tokens)
            fields.append(field)

        if register:
            names.extend(self._names(tokens))

        # If the next token is EOL, consume it
        # Otherwise we're part of a typedef or field definition
        if tokens.next == self.TOK.EOL:
            tokens.eol()

        name = names[0] if names else None

        if st is None:
            is_anonymous = False
            if not name:
                is_anonymous = True
                name = self.cstruct._next_anonymous()

            st = factory(name, fields, align=self.align, anonymous=is_anonymous)
            if self.compiled and "nocompile" not in tokens.flags:
                st = compiler.compile(st)
        else:
            st.__fields__.extend(fields)
            st.commit()

        # This is pretty dirty
        if register:
            if not names and not registered:
                raise ParserError(f"line {self._lineno(stype)}: struct has no name")

            for name in names:
                self.cstruct.add_type(name, st)

        tokens.reset_flags()
        return st

    def _lookup(self, tokens: TokenConsumer) -> None:
        # Just like enums, we cheat and have the entire lookup in the token
        ltok = tokens.consume()

        pattern = self.TOK.patterns[self.TOK.LOOKUP]
        # Dirty trick because the regex expects a ; but we don't want it to be part of the value
        m = pattern.match(ltok.value + ";")
        d = ast.literal_eval(m.group(2))
        self.cstruct.lookups[m.group(1)] = {self.cstruct.consts[k]: v for k, v in d.items()}

    def _parse_field(self, tokens: TokenConsumer) -> Field:
        type_ = None
        if tokens.next == self.TOK.IDENTIFIER:
            type_ = self.cstruct.resolve(self._identifier(tokens))
        elif tokens.next == self.TOK.STRUCT:
            type_ = self._struct(tokens)

            if tokens.next != self.TOK.NAME:
                return Field(None, type_, None)

        if tokens.next != self.TOK.NAME:
            raise ParserError(f"line {self._lineno(tokens.next)}: expected name, got {tokens.next!r}")
        nametok = tokens.consume()

        type_, name, bits = self._parse_field_type(type_, nametok.value)

        tokens.eol()
        return Field(name.strip(), type_, bits)

    def _parse_field_type(self, type_: type[BaseType], name: str) -> tuple[type[BaseType], str, int | None]:
        pattern = self.TOK.patterns[self.TOK.NAME]
        # Dirty trick because the regex expects a ; but we don't want it to be part of the value
        d = pattern.match(name + ";").groupdict()

        name = d["name"]
        count_expression = d["count"]

        while name.startswith("*"):
            name = name[1:]
            type_ = self.cstruct._make_pointer(type_)

        if count_expression is not None:
            # Poor mans multi-dimensional array by abusing the eager regex match of count
            counts = count_expression.split("][") if "][" in count_expression else [count_expression]

            for count in reversed(counts):
                if count == "":
                    count = None
                else:
                    count = Expression(count)
                    try:
                        count = count.evaluate(self.cstruct)
                    except Exception:
                        pass

                if issubclass(type_, BaseArray) and count is None:
                    raise ParserError("Depth required for multi-dimensional array")

                type_ = self.cstruct._make_array(type_, count)

        return type_, name.strip(), int(d["bits"]) if d["bits"] else None

    def _names(self, tokens: TokenConsumer) -> list[str]:
        names = []
        while True:
            if tokens.next == self.TOK.EOL:
                tokens.eol()
                break

            if tokens.next not in (self.TOK.NAME, self.TOK.DEFS, self.TOK.IDENTIFIER):
                break

            ntoken = tokens.consume()
            if ntoken in (self.TOK.NAME, self.TOK.IDENTIFIER):
                names.append(ntoken.value.strip())
            elif ntoken == self.TOK.DEFS:
                names.extend([name.strip() for name in ntoken.value.strip().split(",")])

        return names

    def _include(self, tokens: TokenConsumer) -> None:
        include = tokens.consume()
        pattern = self.TOK.patterns[self.TOK.INCLUDE]
        match = pattern.match(include.value).groupdict()

        self.cstruct.includes.append(match["name"].strip().strip("'\""))

    @staticmethod
    def _remove_comments(string: str) -> str:
        # https://stackoverflow.com/a/18381470
        pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
        # first group captures quoted strings (double or single)
        # second group captures comments (//single-line or /* multi-line */)
        regex = re.compile(pattern, re.MULTILINE | re.DOTALL)

        def _replacer(match: re.Match) -> str:
            # if the 2nd group (capturing comments) is not None,
            # it means we have captured a non-quoted (real) comment string.
            if comment := match.group(2):
                return "\n" * comment.count("\n")  # so we will return empty to remove the comment
            # otherwise, we will return the 1st group
            return match.group(1)  # captured quoted-string

        return regex.sub(_replacer, string)

    @staticmethod
    def _lineno(tok: Token) -> int:
        """Quick and dirty line number calculator."""
        match = tok.match
        return match.string.count("\n", 0, match.start()) + 1

    def _config_flag(self, tokens: TokenConsumer) -> None:
        flag_token = tokens.consume()
        pattern = self.TOK.patterns[self.TOK.CONFIG_FLAG]
        tok_dict = pattern.match(flag_token.value).groupdict()
        tokens.flags.extend(tok_dict["values"].split(","))

    def parse(self, data: str) -> None:
        scanner = re.Scanner(self.TOK.tokens)
        data = self._remove_comments(data)
        tokens, remaining = scanner.scan(data)

        if len(remaining):
            lineno = data.count("\n", 0, len(data) - len(remaining))
            raise ParserError(f"line {lineno}: invalid syntax in definition")

        tokens = TokenConsumer(tokens)
        while True:
            token = tokens.next
            if token is None:
                break

            if self._check_conditional(tokens):
                continue

            if token == self.TOK.CONFIG_FLAG:
                self._config_flag(tokens)
            elif token == self.TOK.DEFINE:
                self._constant(tokens)
            elif token == self.TOK.UNDEF:
                self._undef(tokens)
            elif token == self.TOK.TYPEDEF:
                self._typedef(tokens)
            elif token == self.TOK.STRUCT:
                self._struct(tokens, register=True)
            elif token == self.TOK.ENUM:
                self._enum(tokens)
            elif token == self.TOK.LOOKUP:
                self._lookup(tokens)
            elif token == self.TOK.INCLUDE:
                self._include(tokens)
            else:
                raise ParserError(f"line {self._lineno(token)}: unexpected token {token!r}")

        if self._conditionals:
            raise ParserError(f"line {self._lineno(tokens.previous)}: unclosed conditional statement")


class CStyleParser(Parser):
    """Definition parser for C-like structure syntax (legacy parser).

    Args:
        cs: An instance of cstruct
        compiled: Whether structs should be compiled or not.
    """

    def __init__(self, cs: cstruct, compiled: bool = True):
        self.compiled = compiled
        super().__init__(cs)

    def _constants(self, data: str) -> None:
        r = re.finditer(r"#define\s+(?P<name>[^\s]+)\s+(?P<value>[^\r\n]+)\s*\n", data)
        for t in r:
            d = t.groupdict()
            v = d["value"].rsplit("//")[0]

            try:
                v = ast.literal_eval(v)
            except (ValueError, SyntaxError):
                pass

            self.cstruct.consts[d["name"]] = v

    def _enums(self, data: str) -> None:
        r = re.finditer(
            r"(?P<enumtype>enum|flag)\s+(?P<name>[^\s:{]+)\s*(:\s*(?P<type>[^\s]+)\s*)?\{(?P<values>[^}]+)\}\s*;",
            data,
        )
        for t in r:
            d = t.groupdict()
            enumtype = d["enumtype"]

            nextval = 0
            if enumtype == "flag":
                nextval = 1

            values = {}
            for line in d["values"].split("\n"):
                line, _, _ = line.partition("//")
                for v in line.split(","):
                    key, _, val = v.partition("=")
                    key = key.strip()
                    val = val.strip()
                    if not key:
                        continue

                    val = nextval if not val else Expression(val).evaluate(self.cstruct)

                    if enumtype == "flag":
                        high_bit = val.bit_length() - 1
                        nextval = 2 ** (high_bit + 1)
                    else:
                        nextval = val + 1

                    values[key] = val

            if not d["type"]:
                d["type"] = "uint32"

            factory = self.cstruct._make_enum
            if enumtype == "flag":
                factory = self.cstruct._make_flag

            enum = factory(d["name"], self.cstruct.resolve(d["type"]), values)
            self.cstruct.add_type(enum.__name__, enum)

    def _structs(self, data: str) -> None:
        r = re.finditer(
            r"(#(?P<flags>(?:compile))\s+)?"
            r"((?P<typedef>typedef)\s+)?"
            r"(?P<type>[^\s]+)\s+"
            r"(?P<name>[^\s]+)?"
            r"(?P<fields>"
            r"\s*{[^}]+\}(?P<defs>\s+[^;\n]+)?"
            r")?\s*;",
            data,
        )
        for t in r:
            d = t.groupdict()

            if d["name"]:
                name = d["name"]
            elif d["defs"]:
                name = d["defs"].strip().split(",")[0].strip()
            else:
                raise ParserError("No name for struct")

            if d["type"] == "struct":
                data = self._parse_fields(d["fields"][1:-1].strip())
                st = self.cstruct._make_struct(name, data)
                if d["flags"] == "compile" or self.compiled:
                    st = compiler.compile(st)
            elif d["typedef"] == "typedef":
                st = d["type"]
            else:
                continue

            if d["name"]:
                self.cstruct.add_type(d["name"], st)

            if d["defs"]:
                for td in d["defs"].strip().split(","):
                    td = td.strip()
                    self.cstruct.add_type(td, st)

    def _parse_fields(self, data: str) -> None:
        fields = re.finditer(
            r"(?P<type>[^\s]+)\s+(?P<name>[^\s\[:]+)(:(?P<bits>\d+))?(\[(?P<count>[^;\n]*)\])?;",
            data,
        )

        result = []
        for f in fields:
            d = f.groupdict()
            if d["type"].startswith("//"):
                continue

            type_ = self.cstruct.resolve(d["type"])

            d["name"] = d["name"].replace("(", "").replace(")", "")

            # Maybe reimplement lazy type references later
            # _type = TypeReference(self, d['type'])
            if d["count"] is not None:
                if d["count"] == "":
                    count = None
                else:
                    count = Expression(d["count"])
                    try:
                        count = count.evaluate(self.cstruct)
                    except Exception:
                        pass

                type_ = self.cstruct._make_array(type_, count)

            if d["name"].startswith("*"):
                d["name"] = d["name"][1:]
                type_ = self.cstruct._make_pointer(type_)

            field = Field(d["name"], type_, int(d["bits"]) if d["bits"] else None)
            result.append(field)

        return result

    def _lookups(self, data: str, consts: dict[str, int]) -> None:
        r = re.finditer(r"\$(?P<name>[^\s]+) = ({[^}]+})\w*\n", data)

        for t in r:
            d = ast.literal_eval(t.group(2))
            self.cstruct.lookups[t.group(1)] = {self.cstruct.consts[k]: v for k, v in d.items()}

    def parse(self, data: str) -> None:
        self._constants(data)
        self._enums(data)
        self._structs(data)
        self._lookups(data, self.cstruct.consts)


class Token:
    __slots__ = ("match", "token", "value")

    def __init__(self, token: str, value: str, match: re.Match):
        self.token = token
        self.value = value
        self.match = match

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Token):
            other = other.token

        return self.token == other

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return f"<Token.{self.token} value={self.value!r}>"


class TokenCollection:
    def __init__(self):
        self.tokens: list[Token] = []
        self.lookup: dict[str, str] = {}
        self.patterns: dict[str, re.Pattern] = {}

    def __getattr__(self, attr: str) -> str | Any:
        try:
            return self.lookup[attr]
        except AttributeError:
            pass

        return object.__getattribute__(self, attr)

    def add(self, regex: str, name: str | None) -> None:
        if name is None:
            self.tokens.append((regex, None))
        else:
            self.lookup[name] = name
            self.patterns[name] = re.compile(regex)
            self.tokens.append((regex, lambda s, t: Token(name, t, s.match)))


class TokenConsumer:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.flags = []
        self.previous = None

    def __contains__(self, token: Token) -> bool:
        return token in self.tokens

    def __len__(self) -> int:
        return len(self.tokens)

    def __repr__(self) -> str:
        return f"<TokenConsumer next={self.next!r}>"

    @property
    def next(self) -> Token:
        try:
            return self.tokens[0]
        except IndexError:
            return None

    def consume(self) -> Token:
        self.previous = self.tokens.pop(0)
        return self.previous

    def reset_flags(self) -> None:
        self.flags = []

    def eol(self) -> None:
        token = self.consume()
        if token.token != "EOL":
            raise ParserError(f"line {self._lineno(token)}: expected EOL")
=======
        # If it's still a string, try to evaluate it as an expression in the context of current constants
        if isinstance(value, str):
            try:
                value = Expression(value).evaluate(self.cs)
            except ExpressionParserError:
                # If evaluation fails, just keep it as a string (e.g. for macro-like constants)
                pass

        self.cs.consts[name_token.value] = value

    def _parse_undef(self) -> None:
        """Parse an undef directive and remove the constant."""
        self._expect(TokenType.PP_UNDEF)

        name_token = self._expect(TokenType.IDENTIFIER)
        if name_token.value in self.cs.consts:
            del self.cs.consts[name_token.value]
        else:
            raise self._error(f"constant {name_token.value!r} not defined", token=name_token)

    def _parse_include(self) -> None:
        """Parse an include directive and add the included file to the includes list."""
        self._expect(TokenType.PP_INCLUDE)
        self.cs.includes.append(self._expect(TokenType.STRING).value)

    def _parse_config_flags(self) -> None:
        """Parse configuration flags from a directive like ``#[flag1, flag2, ...]``."""
        self._flags.extend(flag.strip() for flag in self._expect(TokenType.PP_FLAGS).value.split(","))

    def _handle_conditional(self) -> None:
        """Handle conditional directives: ``#ifdef``, ``#ifndef``, ``#else``, ``#endif``."""
        if (token := self._take()).type not in (
            TokenType.PP_IFDEF,
            TokenType.PP_IFNDEF,
            TokenType.PP_ELSE,
            TokenType.PP_ENDIF,
        ):
            raise self._error("expected conditional directive")

        if token.type == TokenType.PP_IFDEF:
            name = self._expect(TokenType.IDENTIFIER).value
            if self._conditional_stack and not self._conditional_stack[-1][1]:
                # Parent is false, so this child is always false
                self._conditional_stack.append((token, False))
            else:
                self._conditional_stack.append((token, name in self.cs.consts))

        elif token.type == TokenType.PP_IFNDEF:
            name = self._expect(TokenType.IDENTIFIER).value
            if self._conditional_stack and not self._conditional_stack[-1][1]:
                self._conditional_stack.append((token, False))
            else:
                self._conditional_stack.append((token, name not in self.cs.consts))

        elif token.type == TokenType.PP_ELSE:
            if not self._conditional_stack:
                raise self._error("#else without matching #ifdef/#ifndef", token=token)

            # Only flip if parent is true (or there's no parent)
            parent_active = len(self._conditional_stack) < 2 or self._conditional_stack[-2][1]
            if parent_active:
                self._conditional_stack[-1] = (self._conditional_stack[-1][0], not self._conditional_stack[-1][1])

        elif token.type == TokenType.PP_ENDIF:
            if not self._conditional_stack:
                raise self._error("#endif without matching #ifdef/#ifndef", token=token)
            self._conditional_stack.pop()

    # Type definitions

    def _parse_typedef(self) -> None:
        """Parse a typedef definition."""
        self._expect(TokenType.TYPEDEF)

        base_type = self._parse_type_spec()

        # Parse one or more typedef names with modifiers (pointers, arrays)
        while self._at(TokenType.IDENTIFIER, TokenType.STAR):
            type_, name, bits = self._parse_field_name(base_type)
            if bits is not None:
                raise self._error("typedefs cannot have bitfields")

            # For convenience, we assign the typedef name to anonymous structs/unions
            if issubclass(base_type, Structure) and base_type.__anonymous__:
                base_type.__anonymous__ = False
                base_type.__name__ = name
                base_type.__qualname__ = name

            self.cs.add_type(name, type_)

            if not self._match(TokenType.COMMA):
                break

        self._match(TokenType.SEMICOLON)

    def _parse_struct_or_union(self) -> type[Structure]:
        """Parse a struct or union definition.

        If ``register`` is ``True``, the struct will be registered with its name (which is required).
        Otherwise, the struct will not be registered and can only be used as an inline type for fields.
        """
        start_token = self._expect(TokenType.STRUCT, TokenType.UNION)

        is_union = start_token.type == TokenType.UNION
        factory = self.cs._make_union if is_union else self.cs._make_struct

        type = None
        name = None

        if not self._at(TokenType.LBRACE):
            if not self._at(TokenType.IDENTIFIER):
                raise self._error("expected struct name or '{'", token=start_token)

            name = self._take().value

            # struct name { ... }
            if self._at(TokenType.LBRACE):
                # Named struct/union, empty pre-register for self-referencing
                type = factory(name, [], align=self.align)
                if self.compiled and "nocompile" not in self._flags:
                    type = compiler.compile(type)
                self.cs.add_type(name, type)
            else:
                # struct typename ... (type reference)
                return self.cs.resolve(name)

        # Parse body
        self._expect(TokenType.LBRACE)
        fields = self._parse_field_list()
        self._expect(TokenType.RBRACE)

        if type is None:
            is_anonymous = name is None
            name = name or self.cs._next_anonymous()

            type = factory(name, fields, align=self.align, anonymous=is_anonymous)
            if self.compiled and "nocompile" not in self._flags:
                type = compiler.compile(type)
        else:
            type.__fields__.extend(fields)
            type.commit()

        self._flags.clear()
        return type

    def _parse_enum_or_flag(self) -> type[Enum | Flag]:
        """Parse an enum or flag definition."""
        start_token = self._expect(TokenType.ENUM, TokenType.FLAG)

        is_flag = start_token.type == TokenType.FLAG

        name = None
        if self._at(TokenType.IDENTIFIER):
            name = self._take().value

        # Optional base type
        base_type_str = "uint32"
        if self._match(TokenType.COLON):
            parts = []
            while (token := self._match(TokenType.IDENTIFIER)) is not None:
                parts.append(token.value)
            base_type_str = " ".join(parts)

        self._expect(TokenType.LBRACE)

        next_value = 1 if is_flag else 0
        values: dict[str, int] = {}

        while not self._at(TokenType.RBRACE):
            self._assert_not_eof()

            member_name = self._expect(TokenType.IDENTIFIER).value

            if self._match(TokenType.EQUALS):
                expression = self._collect_until(TokenType.COMMA, TokenType.RBRACE)
                value = Expression(expression).evaluate(self.cs, values)
            else:
                value = next_value

            if is_flag:
                high_bit = value.bit_length() - 1
                next_value = 2 ** (high_bit + 1)
            else:
                next_value = value + 1

            values[member_name] = value
            self._match(TokenType.COMMA)  # optional trailing comma

        self._expect(TokenType.RBRACE)

        factory = self.cs._make_flag if is_flag else self.cs._make_enum
        type_ = factory(name or "", self.cs.resolve(base_type_str), values)

        if name is not None:
            # Register the enum/flag type if it has a name
            # Anonymous enums/flags are handled in the top level parse loop
            self.cs.add_type(type_.__name__, type_)

        return type_

    # Field parsing

    def _parse_field_list(self) -> list[Field]:
        """Parse a list of fields inside a struct/union body until the closing brace."""
        fields: list[Field] = []

        while not self._at(TokenType.RBRACE):
            self._assert_not_eof()

            fields.append(self._parse_field())

            # Handle multiple fields declared in the same line, e.g., `int x, y, z;` or `struct { ... } a, b;`
            while self._match(TokenType.COMMA):
                type_, name, bits = self._parse_field_name(fields[-1].type)
                fields.append(Field(name, type_, bits))

            self._expect(TokenType.SEMICOLON)

        return fields

    def _parse_field(self) -> Field:
        """Parse a single field declaration."""
        # Regular field: `type name`
        type_ = self._parse_type_spec()

        # Handle the case where a semicolon follows immediately (e.g., anonymous struct/unions)
        if self._at(TokenType.SEMICOLON):
            return Field(None, type_, None)

        type_, name, bits = self._parse_field_name(type_)
        return Field(name, type_, bits)

    def _parse_field_name(self, base_type: type[BaseType]) -> tuple[type[BaseType], str, int | None]:
        """Parses ``'*'* IDENTIFIER ('[' expr? ']')* (':' NUMBER)?``."""
        type_ = base_type

        # Pointer stars
        while self._match(TokenType.STAR):
            type_ = self.cs._make_pointer(type_)

        # Field name
        name = self._expect(*_IDENTIFIER_TYPES).value

        # Array dimensions
        type_ = self._parse_array_dimensions(type_)

        # Bitfield
        bits = None
        if self._match(TokenType.COLON):
            bits = int(self._expect(TokenType.NUMBER).value, 0)

        return type_, name.strip(), bits

    def _parse_array_dimensions(self, base_type: type[BaseType]) -> type[BaseType]:
        """Parse array dimensions following a field name, e.g., ``field[10][20]``."""
        dimensions: list[int | Expression] = []

        while self._match(TokenType.LBRACKET):
            if self._at(TokenType.RBRACKET):
                dimensions.append(None)
            else:
                expression = self._collect_until(TokenType.RBRACKET)
                count = Expression(expression)
                try:
                    count = count.evaluate(self.cs)
                except Exception:
                    pass
                dimensions.append(count)
            self._expect(TokenType.RBRACKET)

        type_ = base_type
        for count in reversed(dimensions):
            if issubclass(type_, BaseArray) and count is None:
                raise ParserError("Depth required for multi-dimensional array")
            type_ = self.cs._make_array(type_, count)

        return type_

    # Type resolution

    def _parse_type_spec(self) -> type[BaseType]:
        """Parse a type specifier, handling multi-word types like ``unsigned long long``.

        Uses lookahead to disambiguate type words from field names: if the next identifier is followed by a
        field delimiter (any of ``;[:,}``) it is the field name, not part of the type — unless the current accumulated
        parts don't form a valid type yet.
        """
        first = self._current()

        # Handle struct/union/enum/flag inline definitions as type specifiers
        if first.type in (TokenType.STRUCT, TokenType.UNION):
            return self._parse_struct_or_union()

        if first.type in (TokenType.ENUM, TokenType.FLAG):
            return self._parse_enum_or_flag()

        # Otherwise, accumulate identifiers for the type specifier until we hit a non-identifier or a field delimiter
        parts = [self._expect(TokenType.IDENTIFIER).value]

        while self._at(TokenType.IDENTIFIER):
            next_after = self._peek(1)

            if next_after.type in (
                TokenType.SEMICOLON,
                TokenType.LBRACKET,
                TokenType.COLON,
                TokenType.COMMA,
                TokenType.RBRACE,
            ):
                # This identifier is followed by a field delimiter, it should be the field name,
                # UNLESS the current parts don't form a valid type yet.
                if " ".join(parts) in self.cs.typedefs:
                    break

                # Current parts don't resolve, consume and hope this completes the type name
                # (will error on resolve if not).
                parts.append(self._take().value)
            elif next_after.type == TokenType.STAR:
                # Field name starts with * (pointer). This identifier is the last type word, consume it and then stop.
                parts.append(self._take().value)
                break
            elif next_after.type == TokenType.IDENTIFIER:
                # More identifiers follow, consume this one as part of the type.
                parts.append(self._take().value)
            else:
                break

        return self.cs.resolve(" ".join(parts))

    # Custom lookup definitions

    def _parse_lookup(self) -> None:
        """Parse a lookup definition."""
        value = self._take().value

        # Parse $name = { dict }
        # Find the name and dict parts
        dollar_rest = value.lstrip("$")
        name, _, lookup = dollar_rest.partition("=")

        d = ast.literal_eval(lookup.strip())
        self.cs.lookups[name.strip()] = {self.cs.consts[k]: v for k, v in d.items()}
>>>>>>> Rewrite lexer and parser

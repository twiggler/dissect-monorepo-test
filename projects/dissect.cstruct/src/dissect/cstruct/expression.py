from __future__ import annotations

<<<<<<< HEAD
import string
from typing import TYPE_CHECKING, ClassVar

from dissect.cstruct.exceptions import ExpressionParserError, ExpressionTokenizerError
=======
from typing import TYPE_CHECKING

from dissect.cstruct.exceptions import ExpressionParserError
from dissect.cstruct.lexer import _IDENTIFIER_TYPES, Lexer, TokenCursor, TokenType
from dissect.cstruct.utils import offsetof, sizeof
>>>>>>> Rewrite lexer and parser

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.cstruct import cstruct
<<<<<<< HEAD


HEXBIN_SUFFIX = {"x", "X", "b", "B"}


class ExpressionTokenizer:
    def __init__(self, expression: str):
        self.expression = expression
        self.pos = 0
        self.tokens = []

    def equal(self, token: str, expected: str | set[str]) -> bool:
        if isinstance(expected, set):
            return token in expected
        return token == expected

    def alnum(self, token: str) -> bool:
        return token.isalnum()

    def alpha(self, token: str) -> bool:
        return token.isalpha()

    def digit(self, token: str) -> bool:
        return token.isdigit()

    def hexdigit(self, token: str) -> bool:
        return token in string.hexdigits

    def operator(self, token: str) -> bool:
        return token in {"*", "/", "+", "-", "%", "&", "^", "|", "(", ")", "~"}

    def match(
        self,
        func: Callable[[str], bool] | None = None,
        expected: str | None = None,
        consume: bool = True,
        append: bool = True,
    ) -> bool:
        if self.eol():
            return False

        token = self.get_token()

        if expected and self.equal(token, expected):
            if append:
                self.tokens.append(token)
            if consume:
                self.consume()
            return True

        if func and func(token):
            if append:
                self.tokens.append(token)
            if consume:
                self.consume()
            return True

        return False

    def consume(self) -> None:
        self.pos += 1

    def eol(self) -> bool:
        return self.pos >= len(self.expression)

    def get_token(self) -> str:
        if self.eol():
            raise ExpressionTokenizerError(f"Out of bounds index: {self.pos}, length: {len(self.expression)}")
        return self.expression[self.pos]

    def tokenize(self) -> list[str]:
        token = ""

        # Loop over expression runs in linear time
        while not self.eol():
            # If token is a single character operand add it to tokens
            if self.match(self.operator):
                continue

            # If token is a single digit, keep looping over expression and build the number
            if self.match(self.digit, consume=False, append=False):
                token += self.get_token()
                self.consume()

                # Support for binary and hexadecimal notation
                if self.match(expected=HEXBIN_SUFFIX, consume=False, append=False):
                    token += self.get_token()
                    self.consume()

                while self.match(self.hexdigit, consume=False, append=False):
                    token += self.get_token()
                    self.consume()
                    if self.eol():
                        break

                # Checks for suffixes in numbers
                if self.match(expected={"u", "U"}, consume=False, append=False):
                    self.consume()
                    self.match(expected={"l", "L"}, append=False)
                    self.match(expected={"l", "L"}, append=False)

                elif self.match(expected={"l", "L"}, append=False):
                    self.match(expected={"l", "L"}, append=False)
                    self.match(expected={"u", "U"}, append=False)
                else:
                    pass

                # Number cannot end on x or b in the case of binary or hexadecimal notation
                if len(token) == 2 and token[-1] in HEXBIN_SUFFIX:
                    raise ExpressionTokenizerError("Invalid binary or hex notation")

                if len(token) > 1 and token[0] == "0" and token[1] not in HEXBIN_SUFFIX:
                    token = token[:1] + "o" + token[1:]
                self.tokens.append(token)
                token = ""

            # If token is alpha or underscore we need to build the identifier
            elif self.match(self.alpha, consume=False, append=False) or self.match(
                expected="_", consume=False, append=False
            ):
                while self.match(self.alnum, consume=False, append=False) or self.match(
                    expected="_", consume=False, append=False
                ):
                    token += self.get_token()
                    self.consume()
                    if self.eol():
                        break
                self.tokens.append(token)
                token = ""
            # If token is length 2 operand make sure next character is part of length 2 operand append to tokens
            elif self.match(expected=">", append=False) and self.match(expected=">", append=False):
                self.tokens.append(">>")
            elif self.match(expected="<", append=False) and self.match(expected="<", append=False):
                self.tokens.append("<<")
            elif self.match(expected={" ", "\n", "\t"}, append=False):
                continue
            else:
                raise ExpressionTokenizerError(
                    f"Tokenizer does not recognize following token '{self.expression[self.pos]}'"
                )
        return self.tokens


class Expression:
    """Expression parser for calculations in definitions."""

    binary_operators: ClassVar[dict[str, Callable[[int, int], int]]] = {
        "|": lambda a, b: a | b,
        "^": lambda a, b: a ^ b,
        "&": lambda a, b: a & b,
        "<<": lambda a, b: a << b,
        ">>": lambda a, b: a >> b,
        "+": lambda a, b: a + b,
        "-": lambda a, b: a - b,
        "*": lambda a, b: a * b,
        "/": lambda a, b: a // b,
        "%": lambda a, b: a % b,
    }

    unary_operators: ClassVar[dict[str, Callable[[int], int]]] = {
        "u": lambda a: -a,
        "~": lambda a: ~a,
    }

    precedence_levels: ClassVar[dict[str, int]] = {
        "|": 0,
        "^": 1,
        "&": 2,
        "<<": 3,
        ">>": 3,
        "+": 4,
        "-": 4,
        "*": 5,
        "/": 5,
        "%": 5,
        "u": 6,
        "~": 6,
        "sizeof": 6,
    }

    def __init__(self, expression: str):
        self.expression = expression
        self.tokens = ExpressionTokenizer(expression).tokenize()
        self.stack = []
        self.queue = []
=======
    from dissect.cstruct.lexer import Token


BINARY_OPERATORS: dict[TokenType, Callable[[int, int], int]] = {
    TokenType.PIPE: lambda a, b: a | b,
    TokenType.CARET: lambda a, b: a ^ b,
    TokenType.AMPERSAND: lambda a, b: a & b,
    TokenType.LSHIFT: lambda a, b: a << b,
    TokenType.RSHIFT: lambda a, b: a >> b,
    TokenType.PLUS: lambda a, b: a + b,
    TokenType.MINUS: lambda a, b: a - b,
    TokenType.STAR: lambda a, b: a * b,
    TokenType.SLASH: lambda a, b: a // b,
    TokenType.PERCENT: lambda a, b: a % b,
}

UNARY_OPERATORS: dict[TokenType, Callable[[int], int]] = {
    TokenType.UNARY_MINUS: lambda a: -a,
    TokenType.TILDE: lambda a: ~a,
}

OPERATORS = set(BINARY_OPERATORS.keys()) | set(UNARY_OPERATORS.keys())

FUNCTION_TOKENS = {
    TokenType.SIZEOF: 1,
    TokenType.OFFSETOF: 2,
}

PRECEDENCE_LEVELS = {
    TokenType.PIPE: 0,
    TokenType.CARET: 1,
    TokenType.AMPERSAND: 2,
    TokenType.LSHIFT: 3,
    TokenType.RSHIFT: 3,
    TokenType.PLUS: 4,
    TokenType.MINUS: 4,
    TokenType.STAR: 5,
    TokenType.SLASH: 5,
    TokenType.PERCENT: 5,
    TokenType.UNARY_MINUS: 6,
    TokenType.TILDE: 6,
    # Functions
    TokenType.SIZEOF: 7,
    TokenType.OFFSETOF: 7,
}


def precedence(o1: TokenType, o2: TokenType) -> bool:
    return PRECEDENCE_LEVELS[o1] >= PRECEDENCE_LEVELS[o2]


class Expression(TokenCursor):
    """Expression parser for calculations in definitions."""

    def __init__(self, expression: str):
        self.expression = expression

        tokens = Lexer(expression).tokenize()
        super().__init__(tokens)
        self._stack: list[TokenType] = []
        self._queue: list[int | str] = []
>>>>>>> Rewrite lexer and parser

    def __repr__(self) -> str:
        return self.expression

<<<<<<< HEAD
    def precedence(self, o1: str, o2: str) -> bool:
        return self.precedence_levels[o1] >= self.precedence_levels[o2]

    def evaluate_exp(self) -> None:
        operator = self.stack.pop(-1)
        res = 0

        if len(self.queue) < 1:
            raise ExpressionParserError("Invalid expression: not enough operands")

        right = self.queue.pop(-1)
        if operator in self.unary_operators:
            res = self.unary_operators[operator](right)
        else:
            if len(self.queue) < 1:
                raise ExpressionParserError("Invalid expression: not enough operands")

            left = self.queue.pop(-1)
            res = self.binary_operators[operator](left, right)

        self.queue.append(res)

    def is_number(self, token: str) -> bool:
        return token.isnumeric() or (len(token) > 2 and token[0] == "0" and token[1] in ("x", "X", "b", "B", "o", "O"))

    def evaluate(self, cs: cstruct, context: dict[str, int] | None = None) -> int:
        """Evaluates an expression using a Shunting-Yard implementation."""
        self.stack = []
        self.queue = []
        operators = set(self.binary_operators.keys()) | set(self.unary_operators.keys())

        context = context or {}
        tmp_expression = self.tokens

        # Unary minus tokens; we change the semantic of '-' depending on the previous token
        for i in range(len(self.tokens)):
            if self.tokens[i] == "-":
                if i == 0:
                    self.tokens[i] = "u"
                    continue
                if self.tokens[i - 1] in operators or self.tokens[i - 1] == "u" or self.tokens[i - 1] == "(":
                    self.tokens[i] = "u"
                    continue

        i = 0
        while i < len(tmp_expression):
            current_token = tmp_expression[i]
            if self.is_number(current_token):
                self.queue.append(int(current_token, 0))
            elif current_token in context:
                self.queue.append(int(context[current_token]))
            elif current_token in cs.consts:
                self.queue.append(int(cs.consts[current_token]))
            elif current_token in self.unary_operators:
                self.stack.append(current_token)
            elif current_token == "sizeof":
                if len(tmp_expression) < i + 3 or (tmp_expression[i + 1] != "(" or tmp_expression[i + 3] != ")"):
                    raise ExpressionParserError("Invalid sizeof operation")
                self.queue.append(len(cs.resolve(tmp_expression[i + 2])))
                i += 3
            elif current_token in operators:
                while (
                    len(self.stack) != 0 and self.stack[-1] != "(" and (self.precedence(self.stack[-1], current_token))
                ):
                    self.evaluate_exp()
                self.stack.append(current_token)
            elif current_token == "(":
                if i > 0:
                    previous_token = tmp_expression[i - 1]
                    if self.is_number(previous_token):
                        raise ExpressionParserError(
                            f"Parser expected sizeof or an arethmethic operator instead got: '{previous_token}'"
                        )

                self.stack.append(current_token)
            elif current_token == ")":
                if i > 0:
                    previous_token = tmp_expression[i - 1]
                    if previous_token == "(":
                        raise ExpressionParserError(
                            f"Parser expected an expression, instead received empty parenthesis. Index: {i}"
                        )

                if len(self.stack) == 0:
                    raise ExpressionParserError("Invalid expression")

                while self.stack[-1] != "(":
                    self.evaluate_exp()

                self.stack.pop(-1)
            else:
                raise ExpressionParserError(f"Unmatched token: '{current_token}'")
            i += 1

        while len(self.stack) != 0:
            if self.stack[-1] == "(":
                raise ExpressionParserError("Invalid expression")

            self.evaluate_exp()

        if len(self.queue) != 1:
            raise ExpressionParserError("Invalid expression")

        return self.queue[0]
=======
    def _reset(self) -> None:
        """Reset the expression state for a new input."""
        self._reset_cursor()
        self._stack = []
        self._queue = []

    def _error(self, msg: str, *, token: Token | None = None) -> ExpressionParserError:
        return ExpressionParserError(f"line {(token if token is not None else self._current()).line}: {msg}")

    def _evaluate_expression(self, cs: cstruct) -> None:
        operator = self._stack.pop(-1)
        result = 0

        if operator in UNARY_OPERATORS:
            if len(self._queue) < 1:
                raise ExpressionParserError("Invalid expression: not enough operands")

            result = UNARY_OPERATORS[operator](self._queue.pop(-1))
        elif operator in BINARY_OPERATORS:
            if len(self._queue) < 2:
                raise ExpressionParserError("Invalid expression: not enough operands")

            right = self._queue.pop(-1)
            left = self._queue.pop(-1)
            result = BINARY_OPERATORS[operator](left, right)
        elif operator in FUNCTION_TOKENS:
            num_args = FUNCTION_TOKENS[operator]
            if len(self._queue) < num_args:
                raise ExpressionParserError("Invalid expression: not enough operands")

            args = [self._queue.pop(-1) for _ in range(num_args)][::-1]
            if operator == TokenType.SIZEOF:
                type_ = cs.resolve(args[0])
                result = sizeof(type_)
            elif operator == TokenType.OFFSETOF:
                type_ = cs.resolve(args[0])
                result = offsetof(type_, args[1])

        self._queue.append(result)

    def evaluate(self, cs: cstruct, context: dict[str, int] | None = None) -> int:
        """Evaluates an expression using a Shunting-Yard implementation."""
        self._reset()
        context = context or {}

        while (token := self._current()).type != TokenType.EOF:
            if token.type == TokenType.NUMBER:
                self._queue.append(int(self._take().value, 0))

            elif token.type in OPERATORS:
                while (
                    len(self._stack) != 0
                    and self._stack[-1] != TokenType.LPAREN
                    and precedence(self._stack[-1], token.type)
                ):
                    self._evaluate_expression(cs)

                self._stack.append(self._take().type)

            elif token.type in FUNCTION_TOKENS:
                func = self._take().type
                self._stack.append(func)

                self._expect(TokenType.LPAREN)

                num_args = FUNCTION_TOKENS[func]
                while num_args > 1:
                    self._queue.append(self._collect_until(TokenType.COMMA))
                    self._expect(TokenType.COMMA)
                    num_args -= 1

                self._queue.append(self._collect_until(TokenType.RPAREN))
                self._expect(TokenType.RPAREN)

                # Evaluate immediately
                self._evaluate_expression(cs)

            elif token.type in _IDENTIFIER_TYPES:
                if token.value in context:
                    self._queue.append(int(context[self._take().value]))

                elif token.value in cs.consts:
                    self._queue.append(int(cs.consts[self._take().value]))

                else:
                    raise self._error(f"Unknown identifier: '{token.value}'", token=token)

            elif token.type == TokenType.LPAREN:
                if self._previous().type == TokenType.NUMBER:
                    raise self._error(
                        f"Parser expected sizeof or an arethmethic operator instead got: '{self._previous().value}'",
                        token=self._previous(),
                    )

                self._stack.append(self._take().type)

            elif token.type == TokenType.RPAREN:
                if self._previous().type == TokenType.LPAREN:
                    raise self._error(
                        "Parser expected an expression, instead received empty parenthesis.",
                        token=self._previous(),
                    )

                if len(self._stack) == 0:
                    raise self._error("Mismatched parentheses")

                while self._stack[-1] != TokenType.LPAREN:
                    self._evaluate_expression(cs)
                    if len(self._stack) == 0:
                        raise self._error("Mismatched parentheses")

                self._stack.pop(-1)  # Pop the '('
                self._take()

            else:
                raise self._error(f"Unmatched token: '{token.value}'", token=token)

        while len(self._stack) != 0:
            if TokenType.LPAREN in self._stack:
                raise self._error("Mismatched parentheses")
            self._evaluate_expression(cs)

        if len(self._queue) != 1:
            raise self._error("Invalid expression: too many operands")

        return self._queue[0]
>>>>>>> Rewrite lexer and parser

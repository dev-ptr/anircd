enum config_type
{
	CFGTYPE_INT,
	CFGTYPE_STRING,
};

typedef struct config_defs_
{
	char	*param;
	enum	config_type type;
	union
	{
		void	*ptr;
		char	**strptr;
		int	*nptr;
	} ptr;
} Config;


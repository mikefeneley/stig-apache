import os
import glob

ROOT = "/"
SERVER_ROOT = "/etc/apache2"
CONFIG_FILE = "apache2.conf"


class ApacheParser:
    """
    ApacheConfParser is used to tokenize config files and couple them
    with relevant information such as file and line number
    """
    def __init__(self, server_root=SERVER_ROOT):
        self.server_root = server_root

    def set_server_root(self, server_root):
        self.server_root = server_root

    def build_directives_list(self, parse_object):
        """
        Returns a list of DirectiveInfo objects for all parse_objects
        contained by parse_object. If parse_object is a file, this
        includes all directives in the file and in files included by
        the file. If parse_object is a directory, it includes all the
        directives of files in the directory and its subdirectories

        :param parse_object: parse_object is the path name of a directory or file
        :type parse_object: string
        :return: a list of directives in the parse_object. 0 is unsuccessful
        """
        directives_list = []

        # Return list of directives contained in files located in
        # directory "parse_object"
        if os.path.isdir(parse_object):
            for root, dirs, files, in os.walk(parse_object):
                for file_object in files:
                    file_path = os.path.join(root, file_object)
                    directives_list += self.build_directives_list(file_path)
            return directives_list

        # Return list of all directives in parse_object and those
        # in files included by parse_objectt
        elif os.path.isfile(parse_object):

            directives_list = self.preprocess_conf(parse_object)

            for i in range(0, len(directives_list)):
                directive = directives_list[i].get_directive()
                options = directives_list[i].get_options()

                if directive == "Include" or directive == "IncludeOptional":
                    include_option = options[0]
                    include_abspath = os.path.join(
                        self.server_root, include_option)
                    matching_paths = glob.glob(include_abspath)

                    for object_path in matching_paths:
                        directives_list += self.build_directives_list(
                            object_path)
            return directives_list
        else:
            return 0

    def preprocess_conf(self, conf_filename):
        """
        Parse a configuration file and return all directives in a list
        of directive_info objects

        :param conf_filename: configuartion filename
        :type conf_filename: string
        :return: list of directives
        """
        directive_list = self.load_config(conf_filename)
        directive_list = self.combine_multiline(directive_list)
        directive_list = self.tokenize_directives(
            directive_list, conf_filename)
        return directive_list

    def load_config(self, conf_filename):
        """
        Load every line in a configuration file into a list.
        :param config_list: the configuration file to parse
        :type config_list: string
        :return: list of config lines
        """
        conf_file = open(conf_filename, "r")
        directive_list = []
        for line in conf_file:
            directive_list.append(line)
        conf_file.close()
        return directive_list

    def combine_multiline(self, config_list):
        """
        Take multiline directives in the configuartion file conjoined
        with the \\ characters and put them on the same line.

        :param config_list: the configuration file to parse
        :type config_list: string
        :return: list of combined directives
        """
        holder = []
        i = 0
        while i < len(config_list):
            next = i + 1
            line = config_list[i]
            complete_line = line
            while line[len(line) - 2] == '\\' and next < len(config_list):
                line = config_list[next]
                complete_line = complete_line[0:len(complete_line) - 2] + line
                next += 1
            holder.append((complete_line, i))
            i = next
        return holder

    def tokenize_directives(self, config_list, conf_filename):
        """
        Parse a list of directives and remove all tabs, newline characters
        and comments.

        :param config_list: the configuration list to parse
        :type config_list: list
        :param conf_filename: Name of the configuration file.
        :type conf_filename: string
        :return: list of combined directives
        """
        holder = []
        i = 0
        while i < len(config_list):
            directive_info = config_list[i]
            directive = directive_info[0]
            line_num = directive_info[1]
            filtered_directive = directive.replace("\t", " ")
            filtered_directive = filtered_directive.strip("\n ")
            if filtered_directive != "" and filtered_directive[0] != '#':
                tokens = filtered_directive.split()
                directive = tokens[0]
                options = tokens[1:len(tokens)]
                line = DirectiveLine(directive, options)
                info = DirectiveInfo(line, line_num, conf_filename)
                holder.append(info)
            i += 1
        return holder


class DirectiveInfo:
    """
    Directive info holds directive as well as information useful
    or recomendation reporting such as filenames and line numbers
    """

    def __init__(self, directive_line, line_num, filename):
        self.directive_line = directive_line
        self.line_num = line_num
        self.filename = filename

    def get_directive(self):
        return self.directive_line.directive

    def get_options(self):
        return self.directive_line.options

    def get_line_num(self):
        return self.line_num

    def get_line(self):
        line = list(self.directive_line.options)
        directive = self.get_directive()
        line.insert(0, directive)
        return line

    def get_filename(self):
        return self.filename

    def status(self):
        print (
            self.get_directive(),
            self.get_options(),
            self.get_line_num(),
            self.get_filename())


class DirectiveLine:

    def __init__(self, directive, options):
        self.directive = directive
        self.options = options

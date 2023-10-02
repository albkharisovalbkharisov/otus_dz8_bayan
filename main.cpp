#include <algorithm>
#include <boost/filesystem/directory.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/iostreams/device/mapped_file.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/iostreams/device/file.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/filesystem.hpp>
#include <boost/optional.hpp>
#include <iostream>
#include <vector>
#include <list>
#include <map>
#include <memory>

#include <boost/program_options.hpp>
#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/program_options.hpp>

using boost::uuids::detail::md5;
namespace bf = boost::filesystem;
namespace bpo = boost::program_options;
using mapfile = boost::iostreams::mapped_file_source;
static size_t block_size = 10;

class FileComparator
{
public:
    FileComparator(const FileComparator& other) = delete;
    FileComparator& operator=(const FileComparator& other) = delete;

    FileComparator() : path{} {}

    FileComparator(bf::path name)
        : path(name), file_size(bf::file_size(path)) {}

    ~FileComparator() {
        if (file.is_open()) {file.close();}
    }

    FileComparator& operator=(FileComparator&& other)
    {
        file = std::move(other.file);
        path = other.path;
        file_size = other.file_size;

        return *this;
    }

    bool operator==(const FileComparator& other) const
    {
        if (file_size != other.file_size)
        {
            return false;
        }

        bool result = true;
        reset_comparison();
        other.reset_comparison();
        for (size_t file_ptr = 0; file_ptr < file_size; file_ptr += block_size)
        {
            if (get_hash() != other.get_hash())
            {
                result = false;
            }
        }

        if (file.is_open()) {
            file.close();
        }
        if (other.file.is_open()) {
            other.file.close();
        }

        return result;
    }

    bf::path get_file_name() const
    {
        return path;
    }

private:
    using HashStr = std::string;
    using ListMd5 = std::list<HashStr>;

    bf::path path;
    mutable ListMd5 hash_list;
    mutable ListMd5::const_iterator it;
    mutable size_t offset;
    size_t file_size;
    const char* data;
    mutable mapfile file;

    void reset_comparison(void) const
    {
        it = hash_list.cbegin();
        offset = 0;
    }

    HashStr get_hash() const
    {
        if (it != hash_list.cend())
        {
            return *it++;
        }

        add_hash();
        return hash_list.back();
    }

    void add_hash(void) const
    {
        if (!file.is_open()) {
            file.open(path, file_size, 0);
        }

        auto read_size = std::min(block_size, file_size - offset);

        auto data0 = std::unique_ptr<char[]>(new char[block_size]);
        memcpy(data0.get(), file.data() + offset, read_size);

        md5 hash;
        md5::digest_type digest;
        hash.process_bytes(data0.get(), block_size);
        hash.get_digest(digest);

        offset += block_size;
        hash_list.push_back(toString(digest));
    }

    std::string toString(const md5::digest_type &digest) const
    {
        const auto charDigest = reinterpret_cast<const char *>(&digest);
        std::string result;
        boost::algorithm::hex(charDigest, charDigest + sizeof(md5::digest_type), std::back_inserter(result));
        return result;
    }
};

class PairsFinder
{
using rdit = bf::recursive_directory_iterator;

public:
    PairsFinder(const bf::path& p, const std::string& filter) : path(p) {}

    void process(std::function<void(bf::path, bf::path)> f)
    {
        int i = 1;
        for (auto left = rdit{path}; left != rdit{}; ++left, ++i)
        {
            if (!bf::is_regular_file(*left))
                continue;

            auto right = rdit{path};
            for (int j = 0; j < i; ++j) {
                ++right;
            }

            for (; right != rdit{}; ++right)
            {
                if (!bf::is_regular_file(*right))
                    continue;

                f(*left, *right);
            }
        }
    }

    void list_files(void)
    {
        for (auto it = rdit{path}; it != rdit{}; ++it)
        {
            if (!bf::is_regular_file(*it))
                continue;
            std::cout << *it << std::endl;
        }
    }

private:
    bf::path path;
    std::string filter;
    size_t depth;
};


class FileComparatorStorage
{
    using MapComp = std::map<bf::path, FileComparator>;
    MapComp map_comp;

public:
    const FileComparator& get_comparator(const bf::path& name)
    {
        const auto comp = map_comp.find(name);
        if (comp == map_comp.cend())
        {
            map_comp[name] = FileComparator{name};
        }
        return map_comp[name];
    }
};

class SimilarFileGroups
{
using SetOfFiles = std::set<bf::path>;

public:
    void add_files(const bf::path& file1, const bf::path& file2)
    {
        bool found = false;
        for (auto& fileset : groups) {
            if ((fileset.find(file1) != fileset.cend())
                || (fileset.find(file2) != fileset.cend()))
            {
                fileset.emplace(file1);
                fileset.emplace(file2);
                found = true;
                break;
            }
        }

        if (!found) {
            auto new_set = SetOfFiles{file1};
            new_set.emplace(file2);
            groups.emplace_back(new_set);
        }
    }

    const std::list<SetOfFiles>& get_groups(void) const
    {
        return groups;
    }

private:
    std::list<SetOfFiles> groups;
};

int main(int argc, const char *argv[])
{
    std::string dirs{};
    std::string filter{};

    try {
        bpo::options_description desc{"Options"};
        desc.add_options()
                ("help,h", "This screen")
                ("dirs,d", bpo::value<std::string>(&dirs)->default_value("./data"), "Directories to search")
                ("filter,f", bpo::value<std::string>(&filter)->default_value(".*"), "Filter of files. Process only files that pass the filter")
                ("block_size,bs", bpo::value<size_t>(&block_size)->default_value(10), "Processing blocks size");
        bpo::variables_map vm;
        bpo::store(parse_command_line(argc, argv, desc), vm);
        notify(vm);

        if (vm.count("help")) {
            std::cout << desc << '\n';
            return 0;
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        std::cout << "Terminate program" << std::endl;
        return -1;
    }

    std::cout << "block_size: " << block_size << std::endl;
    std::cout << "filter: " << filter << std::endl;

    std::stringstream ss(dirs);
    std::string dir;
    while (getline(ss, dir, ' ')) {
        if (dir.empty())
            continue;
        std::cout << "Directory: \'" << dir << "\'" << std::endl;

        auto groups = SimilarFileGroups{};
        auto pairs_finder = PairsFinder{bf::path(dir), filter};
        auto storage = FileComparatorStorage{};

        pairs_finder.process(
                [&storage, &groups](auto left, auto right)
                {
                    const auto& l = storage.get_comparator(left);
                    const auto& r = storage.get_comparator(right);
                    if (l == r) {
//                        std::cout << "EQUAL: " << left << " : " << right << std::endl;
                        groups.add_files(l.get_file_name(), r.get_file_name());
                    }
                });

        int i = 0;
        for (const auto& fileset : groups.get_groups()) {
            std::for_each(fileset.cbegin(), fileset.cend(), [] (auto file)
                    {
                        std::cout << file << std::endl;
                    });
            std::cout << std::endl;
        }
    }

    return 0;
}


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

#include <boost/uuid/detail/md5.hpp>
#include <boost/algorithm/hex.hpp>

using boost::uuids::detail::md5;
namespace bf = boost::filesystem;
using mapfile = boost::iostreams::mapped_file_source;
static constexpr size_t block_size = 10;

class FileComparator
{
public:
    FileComparator(const FileComparator& other) = delete;
    FileComparator& operator=(const FileComparator& other) = delete;

    FileComparator() : path{std::string{"123"}} {}

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

        return result && (file_size == other.file_size);
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

        char data0[block_size] = {0};
        memcpy(data0, file.data() + offset, read_size);

        md5 hash;
        md5::digest_type digest;
        hash.process_bytes(data0, block_size);
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
    PairsFinder(const bf::path& p) : path(p) {}

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

    bf::path path;
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

int main()
{
    auto pairs_finder = PairsFinder{bf::current_path() / "data"};
    auto storage = FileComparatorStorage{};

    pairs_finder.process(
            [&storage](auto left, auto right)
            {
                const auto& l = storage.get_comparator(left);
                const auto& r = storage.get_comparator(right);
                if (l == r) {
                    std::cout << "EQUAL: " << left << " : " << right << std::endl;
                }
            });

    return 0;
}


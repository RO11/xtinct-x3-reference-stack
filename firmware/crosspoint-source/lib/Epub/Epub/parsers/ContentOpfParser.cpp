#include "ContentOpfParser.h"

#include <FsHelpers.h>
#include <Logging.h>
#include <Serialization.h>
#include <XmlParserUtils.h>

#include <cctype>

#include "Epub/BookMetadataCache.h"

namespace {
constexpr char MEDIA_TYPE_NCX[] = "application/x-dtbncx+xml";
constexpr char MEDIA_TYPE_CSS[] = "text/css";
constexpr char MEDIA_TYPE_IMAGE_PREFIX[] = "image/";
constexpr char itemCacheFile[] = "/.items.bin";

bool startsWithImageMediaType(const std::string& mediaType) {
  constexpr size_t prefixLen = sizeof(MEDIA_TYPE_IMAGE_PREFIX) - 1;
  if (mediaType.size() < prefixLen) {
    return false;
  }

  for (size_t i = 0; i < prefixLen; ++i) {
    const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(mediaType[i])));
    if (c != MEDIA_TYPE_IMAGE_PREFIX[i]) {
      return false;
    }
  }

  return true;
}

bool boundedAttribute(const char* const value, const size_t maximum) {
  return value && strnlen(value, maximum + 1) <= maximum;
}
}  // namespace

void ContentOpfParser::failParsing(const char* const reason) {
  if (failed) return;
  failed = true;
  LOG_ERR("COF", "Rejected content.opf: %s", reason ? reason : "invalid input");
  if (parser) XML_StopParser(parser, XML_FALSE);
}

bool ContentOpfParser::setup() {
  if (remainingSize == 0 || remainingSize > epub::limits::MAX_EPUB_RESOURCE_BYTES ||
      baseContentPath.size() > epub::limits::MAX_HREF_BYTES) {
    failed = true;
    LOG_ERR("COF", "Rejected invalid OPF size or base path");
    return false;
  }
  parser = XML_ParserCreate(nullptr);
  if (!parser) {
    LOG_DBG("COF", "Couldn't allocate memory for parser");
    return false;
  }

  XML_SetUserData(parser, this);
  XML_SetElementHandler(parser, startElement, endElement);
  XML_SetCharacterDataHandler(parser, characterData);
  return true;
}

ContentOpfParser::~ContentOpfParser() {
  destroyXmlParser(parser);
  if (tempItemStore) {
    tempItemStore.close();
  }
  const auto itemCachePath = cachePath + itemCacheFile;
  if (Storage.exists(itemCachePath.c_str())) {
    Storage.remove(itemCachePath.c_str());
  }
}

size_t ContentOpfParser::write(const uint8_t data) { return write(&data, 1); }

size_t ContentOpfParser::write(const uint8_t* buffer, const size_t size) {
  if (!parser || failed || size > remainingSize) {
    if (size > remainingSize) failParsing("stream exceeds declared OPF size");
    return 0;
  }

  const uint8_t* currentBufferPos = buffer;
  auto remainingInBuffer = size;

  while (remainingInBuffer > 0) {
    void* const buf = XML_GetBuffer(parser, 1024);

    if (!buf) {
      LOG_ERR("COF", "Couldn't allocate memory for buffer");
      failed = true;
      destroyXmlParser(parser);
      parser = nullptr;
      return 0;
    }

    const auto toRead = remainingInBuffer < 1024 ? remainingInBuffer : 1024;
    memcpy(buf, currentBufferPos, toRead);

    if (XML_ParseBuffer(parser, static_cast<int>(toRead), remainingSize == toRead) == XML_STATUS_ERROR) {
      LOG_DBG("COF", "Parse error at line %lu: %s", XML_GetCurrentLineNumber(parser),
              XML_ErrorString(XML_GetErrorCode(parser)));
      failed = true;
      destroyXmlParser(parser);
      parser = nullptr;
      return 0;
    }

    currentBufferPos += toRead;
    remainingInBuffer -= toRead;
    remainingSize -= toRead;
  }

  return size;
}

void XMLCALL ContentOpfParser::startElement(void* userData, const XML_Char* name, const XML_Char** atts) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (!epub::limits::catchAllocationFailure([&]() { startElementImpl(userData, name, atts); })) {
    self->failParsing("allocation failed in start-element callback");
  }
}

void ContentOpfParser::startElementImpl(void* userData, const XML_Char* name, const XML_Char** atts) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (self->failed) return;

  if (self->state == START && (strcmp(name, "package") == 0 || strcmp(name, "opf:package") == 0)) {
    self->state = IN_PACKAGE;
    return;
  }

  if (self->state == IN_PACKAGE && (strcmp(name, "metadata") == 0 || strcmp(name, "opf:metadata") == 0)) {
    self->state = IN_METADATA;
    return;
  }

  if (self->state == IN_METADATA && strcmp(name, "dc:title") == 0) {
    // Only capture the first dc:title element; subsequent ones are subtitles
    if (self->title.empty()) {
      self->state = IN_BOOK_TITLE;
    }
    return;
  }

  if (self->state == IN_METADATA && strcmp(name, "dc:creator") == 0) {
    // Separate creator elements, not Expat character-data chunks. Expat may
    // split one creator's text arbitrarily, so inserting a comma in
    // characterData corrupts otherwise valid author names.
    if (!self->author.empty()) {
      if (!epub::limits::countCanGrow(self->author.size(), 2, epub::limits::MAX_AUTHOR_BYTES)) {
        self->failParsing("author too long");
        return;
      }
      self->author.append(", ");
    }
    self->state = IN_BOOK_AUTHOR;
    return;
  }

  if (self->state == IN_METADATA && strcmp(name, "dc:language") == 0) {
    self->state = IN_BOOK_LANGUAGE;
    return;
  }

  if (self->state == IN_PACKAGE && (strcmp(name, "manifest") == 0 || strcmp(name, "opf:manifest") == 0)) {
    self->state = IN_MANIFEST;
    if (!Storage.openFileForWrite("COF", self->cachePath + itemCacheFile, self->tempItemStore)) {
      self->failParsing("could not open manifest temp store for writing");
    }
    return;
  }

  if (self->state == IN_PACKAGE && (strcmp(name, "spine") == 0 || strcmp(name, "opf:spine") == 0)) {
    self->state = IN_SPINE;
    if (!Storage.openFileForRead("COF", self->cachePath + itemCacheFile, self->tempItemStore)) {
      self->failParsing("could not open manifest temp store for spine lookup");
      return;
    }

    // Sort the (unconditionally-built) item index so every idref lookup uses binary
    // search. Without this, small/medium manifests fell back to an O(spine × manifest)
    // linear rescan of .items.bin per itemref (up to ~200ms/item at large scale).
    if (!self->itemIndex.empty()) {
      std::sort(self->itemIndex.begin(), self->itemIndex.end(), [](const ItemIndexEntry& a, const ItemIndexEntry& b) {
        return a.idHash < b.idHash || (a.idHash == b.idHash && a.idLen < b.idLen);
      });
      self->useItemIndex = true;
      LOG_DBG("COF", "Using fast index for %zu manifest items", self->itemIndex.size());
    }
    return;
  }

  if (self->state == IN_PACKAGE && (strcmp(name, "guide") == 0 || strcmp(name, "opf:guide") == 0)) {
    self->state = IN_GUIDE;
    // TODO Remove print
    LOG_DBG("COF", "Entering guide state.");
    if (!Storage.openFileForRead("COF", self->cachePath + itemCacheFile, self->tempItemStore)) {
      self->failParsing("could not open manifest temp store for guide lookup");
      return;
    }
    return;
  }

  if (self->state == IN_METADATA && (strcmp(name, "meta") == 0 || strcmp(name, "opf:meta") == 0)) {
    bool isCover = false;
    std::string coverItemId;

    for (int i = 0; atts[i]; i += 2) {
      if (strcmp(atts[i], "name") == 0 && strcmp(atts[i + 1], "cover") == 0) {
        isCover = true;
      } else if (strcmp(atts[i], "content") == 0) {
        if (!boundedAttribute(atts[i + 1], epub::limits::MAX_ITEM_ID_BYTES)) {
          self->failParsing("cover item id too long");
          return;
        }
        coverItemId = atts[i + 1];
      }
    }

    if (isCover) {
      self->coverItemId = coverItemId;
    }
    return;
  }

  if (self->state == IN_MANIFEST && (strcmp(name, "item") == 0 || strcmp(name, "opf:item") == 0)) {
    if (self->manifestItemCount >= epub::limits::MAX_MANIFEST_ITEMS) {
      self->failParsing("manifest item count exceeds limit");
      return;
    }
    std::string itemId;
    std::string href;
    std::string mediaType;
    std::string properties;

    for (int i = 0; atts[i]; i += 2) {
      if (strcmp(atts[i], "id") == 0) {
        if (!boundedAttribute(atts[i + 1], epub::limits::MAX_ITEM_ID_BYTES)) {
          self->failParsing("manifest id too long");
          return;
        }
        itemId = atts[i + 1];
      } else if (strcmp(atts[i], "href") == 0) {
        if (!boundedAttribute(atts[i + 1], epub::limits::MAX_HREF_BYTES)) {
          self->failParsing("manifest href too long");
          return;
        }
        href = FsHelpers::normalisePath(FsHelpers::decodeUriEscapes(self->baseContentPath + atts[i + 1]));
      } else if (strcmp(atts[i], "media-type") == 0) {
        if (!boundedAttribute(atts[i + 1], 256)) {
          self->failParsing("manifest media type too long");
          return;
        }
        mediaType = atts[i + 1];
      } else if (strcmp(atts[i], "properties") == 0) {
        if (!boundedAttribute(atts[i + 1], 512)) {
          self->failParsing("manifest properties too long");
          return;
        }
        properties = atts[i + 1];
      }
    }
    if (itemId.empty() || href.empty() || href.size() > epub::limits::MAX_HREF_BYTES) {
      self->failParsing("manifest item is missing or oversized");
      return;
    }
    self->manifestItemCount++;

    // Record index entry for fast lookup later
    if (self->tempItemStore) {
      ItemIndexEntry entry;
      entry.idHash = fnvHash(itemId);
      entry.idLen = static_cast<uint16_t>(itemId.size());
      entry.fileOffset = static_cast<uint32_t>(self->tempItemStore.position());
      if (!epub::limits::checkedVectorPushBack(self->itemIndex, entry, epub::limits::MAX_MANIFEST_ITEMS)) {
        self->failParsing("manifest index allocation refused");
        return;
      }
    }

    // Write items down to SD card
    if (!serialization::writeString(self->tempItemStore, itemId) ||
        !serialization::writeString(self->tempItemStore, href)) {
      self->failParsing("manifest temp store write failed");
      return;
    }

    if (itemId == self->coverItemId) {
      // Some EPUBs set meta name="cover" to an XHTML wrapper item.
      // Only treat it as a cover image when the manifest media-type is image/*.
      if (startsWithImageMediaType(mediaType)) {
        self->coverItemHref = href;
      } else {
        LOG_DBG("COF", "Ignoring meta cover item '%s' with non-image media type: %s", itemId.c_str(),
                mediaType.c_str());
      }
    }

    if (mediaType == MEDIA_TYPE_NCX) {
      if (self->tocNcxPath.empty()) {
        self->tocNcxPath = href;
      } else {
        LOG_DBG("COF", "Warning: Multiple NCX files found in manifest. Ignoring duplicate: %s", href.c_str());
      }
    }

    // EPUB 3: Check for nav document (properties contains "nav")
    if (!properties.empty() && self->tocNavPath.empty()) {
      // Properties is space-separated, check if "nav" is present as a word
      if (properties == "nav" || properties.starts_with("nav ") || properties.find(" nav") != std::string::npos) {
        self->tocNavPath = href;
        LOG_DBG("COF", "Found EPUB 3 nav document: %s", href.c_str());
      }
    }

    // EPUB 3: Check for cover image (properties contains "cover-image")
    if (!properties.empty() && self->coverItemHref.empty()) {
      if (properties == "cover-image" || properties.starts_with("cover-image ") ||
          properties.find(" cover-image") != std::string::npos) {
        self->coverItemHref = href;
      }
    }

    // This is deliberately last: ownership of the href moves into the retained
    // CSS list, so no second path payload remains live in the parser.
    if (mediaType == MEDIA_TYPE_CSS) {
      const size_t hrefCharge = href.size() + 1;
      if (!epub::limits::countCanGrow(self->cssHrefBytes, hrefCharge, epub::limits::MAX_CSS_HREF_BYTES) ||
          !epub::limits::checkedVectorPushBack(self->cssFiles, std::move(href), epub::limits::MAX_CSS_FILES)) {
        self->failParsing("CSS href aggregate or allocation limit exceeded");
        return;
      }
      self->cssHrefBytes += hrefCharge;
    }
    return;
  }

  // NOTE: This relies on spine appearing after item manifest (which is pretty safe as it's part of the EPUB spec)
  // Only run the spine parsing if there's a cache to add it to
  if (self->cache) {
    if (self->state == IN_SPINE && (strcmp(name, "itemref") == 0 || strcmp(name, "opf:itemref") == 0)) {
      for (int i = 0; atts[i]; i += 2) {
        if (strcmp(atts[i], "idref") == 0) {
          if (!boundedAttribute(atts[i + 1], epub::limits::MAX_ITEM_ID_BYTES)) {
            self->failParsing("spine idref too long");
            return;
          }
          const std::string idref = atts[i + 1];
          std::string href;
          bool found = false;

          if (self->useItemIndex) {
            // Fast path: binary search
            uint32_t targetHash = fnvHash(idref);
            uint16_t targetLen = static_cast<uint16_t>(idref.size());

            auto it = std::lower_bound(self->itemIndex.begin(), self->itemIndex.end(),
                                       ItemIndexEntry{targetHash, targetLen, 0},
                                       [](const ItemIndexEntry& a, const ItemIndexEntry& b) {
                                         return a.idHash < b.idHash || (a.idHash == b.idHash && a.idLen < b.idLen);
                                       });

            // Check for match (may need to check a few due to hash collisions)
            while (it != self->itemIndex.end() && it->idHash == targetHash) {
              self->tempItemStore.seek(it->fileOffset);
              std::string itemId;
              if (!serialization::readString(self->tempItemStore, itemId, epub::limits::MAX_ITEM_ID_BYTES)) {
                self->failParsing("malformed manifest temp id");
                return;
              }
              if (itemId == idref) {
                if (!serialization::readString(self->tempItemStore, href, epub::limits::MAX_HREF_BYTES)) {
                  self->failParsing("malformed manifest temp href");
                  return;
                }
                found = true;
                break;
              }
              ++it;
            }
          } else {
            // Fallback linear scan, only reached when the index is empty (no manifest
            // items). The fast binary-search path above is used for all real manifests.
            self->tempItemStore.seek(0);
            std::string itemId;
            while (self->tempItemStore.available()) {
              if (!serialization::readString(self->tempItemStore, itemId, epub::limits::MAX_ITEM_ID_BYTES) ||
                  !serialization::readString(self->tempItemStore, href, epub::limits::MAX_HREF_BYTES)) {
                self->failParsing("malformed manifest temp record");
                return;
              }
              if (itemId == idref) {
                found = true;
                break;
              }
            }
          }

          if (found && self->cache) {
            if (!self->cache->createSpineEntry(href)) {
              self->failParsing("spine count or href exceeds limit");
              return;
            }
          }
        }
      }
      return;
    }
  }
  // parse the guide
  if (self->state == IN_GUIDE && (strcmp(name, "reference") == 0 || strcmp(name, "opf:reference") == 0)) {
    std::string type;
    std::string guideHref;
    for (int i = 0; atts[i]; i += 2) {
      if (strcmp(atts[i], "type") == 0) {
        if (!boundedAttribute(atts[i + 1], 64)) {
          self->failParsing("guide type too long");
          return;
        }
        type = atts[i + 1];
      } else if (strcmp(atts[i], "href") == 0) {
        if (!boundedAttribute(atts[i + 1], epub::limits::MAX_HREF_BYTES)) {
          self->failParsing("guide href too long");
          return;
        }
        guideHref = FsHelpers::normalisePath(FsHelpers::decodeUriEscapes(self->baseContentPath + atts[i + 1]));
      }
    }
    if (guideHref.size() > epub::limits::MAX_HREF_BYTES) {
      self->failParsing("normalized guide href too long");
      return;
    }
    if (!guideHref.empty()) {
      // EPUB 2 guides often mark every content file as "text", so that type
      // does not identify a reliable first-reading location. Only use the
      // explicit "start" semantic; otherwise the reader opens at spine index 0.
      if (type == "start" && !self->hasExplicitStartReference) {
        LOG_DBG("COF", "Found %s reference in guide: %s", type.c_str(), guideHref.c_str());
        self->textReferenceHref = guideHref;
        self->hasExplicitStartReference = type == "start";
      } else if ((type == "cover" || type == "cover-page") && self->guideCoverPageHref.empty()) {
        LOG_DBG("COF", "Found cover reference in guide: %s", guideHref.c_str());
        self->guideCoverPageHref = guideHref;
      }
    }
    return;
  }
}

void XMLCALL ContentOpfParser::characterData(void* userData, const XML_Char* s, const int len) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (!epub::limits::catchAllocationFailure([&]() { characterDataImpl(userData, s, len); })) {
    self->failParsing("allocation failed in character-data callback");
  }
}

void ContentOpfParser::characterDataImpl(void* userData, const XML_Char* s, const int len) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (self->failed || len < 0) return;

  const auto appendBounded = [self, s, len](std::string& target, const size_t maximum, const char* reason) {
    if (static_cast<size_t>(len) > maximum || target.size() > maximum - static_cast<size_t>(len) ||
        target.size() + static_cast<size_t>(len) > maximum) {
      self->failParsing(reason);
      return false;
    }
    target.append(s, len);
    return true;
  };

  if (self->state == IN_BOOK_TITLE) {
    appendBounded(self->title, epub::limits::MAX_TITLE_BYTES, "title too long");
    return;
  }

  if (self->state == IN_BOOK_AUTHOR) {
    appendBounded(self->author, epub::limits::MAX_AUTHOR_BYTES, "author too long");
    return;
  }

  if (self->state == IN_BOOK_LANGUAGE) {
    appendBounded(self->language, epub::limits::MAX_LANGUAGE_BYTES, "language too long");
    return;
  }
}

void XMLCALL ContentOpfParser::endElement(void* userData, const XML_Char* name) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (!epub::limits::catchAllocationFailure([&]() { endElementImpl(userData, name); })) {
    self->failParsing("allocation failed in end-element callback");
  }
}

void ContentOpfParser::endElementImpl(void* userData, const XML_Char* name) {
  auto* self = static_cast<ContentOpfParser*>(userData);
  if (self->failed) return;

  if (self->state == IN_SPINE && (strcmp(name, "spine") == 0 || strcmp(name, "opf:spine") == 0)) {
    self->state = IN_PACKAGE;
    self->tempItemStore.close();
    return;
  }

  if (self->state == IN_GUIDE && (strcmp(name, "guide") == 0 || strcmp(name, "opf:guide") == 0)) {
    self->state = IN_PACKAGE;
    self->tempItemStore.close();
    return;
  }

  if (self->state == IN_MANIFEST && (strcmp(name, "manifest") == 0 || strcmp(name, "opf:manifest") == 0)) {
    self->state = IN_PACKAGE;
    self->tempItemStore.close();
    return;
  }

  if (self->state == IN_BOOK_TITLE && strcmp(name, "dc:title") == 0) {
    self->state = IN_METADATA;
    return;
  }

  if (self->state == IN_BOOK_AUTHOR && strcmp(name, "dc:creator") == 0) {
    self->state = IN_METADATA;
    return;
  }

  if (self->state == IN_BOOK_LANGUAGE && strcmp(name, "dc:language") == 0) {
    self->state = IN_METADATA;
    return;
  }

  if (self->state == IN_METADATA && (strcmp(name, "metadata") == 0 || strcmp(name, "opf:metadata") == 0)) {
    self->state = IN_PACKAGE;
    return;
  }

  if (self->state == IN_PACKAGE && (strcmp(name, "package") == 0 || strcmp(name, "opf:package") == 0)) {
    self->state = START;
    return;
  }
}

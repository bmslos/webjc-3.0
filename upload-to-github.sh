#!/bin/bash
# webjc-pro 一键上传到GitHub脚本
# 使用方法: 
#   Linux/Mac: ./upload-to-github.sh
#   Windows: 在Git Bash中运行 bash upload-to-github.sh

echo "========================================="
echo "webjc-pro 上传到GitHub工具"
echo "========================================="
echo ""

# 检查是否在正确的目录
if [ ! -f "main.py" ]; then
    echo "❌ 错误: 请在webjc-pro目录下运行此脚本"
    exit 1
fi

echo "✅ 目录检查通过"
echo ""

# 显示当前Git状态
echo "📊 当前Git状态:"
git status --short
echo ""

# 显示提交历史
echo "📝 最近提交:"
git log --oneline -5
echo ""

# 检查远程仓库
echo "🔗 远程仓库配置:"
git remote -v
echo ""

if git remote | grep -q "origin"; then
    echo "⚠️  远程仓库'origin'已存在"
    echo ""
    read -p "是否要更新远程仓库? (y/n): " update_remote
    if [ "$update_remote" != "y" ]; then
        echo "❌ 已取消操作"
        exit 0
    fi
else
    echo "📝 需要添加远程仓库"
    echo ""
    read -p "请输入你的GitHub用户名: " github_username
    
    if [ -z "$github_username" ]; then
        echo "❌ 用户名不能为空"
        exit 1
    fi
    
    echo ""
    echo "选择认证方式:"
    echo "1) HTTPS (推荐新手)"
    echo "2) SSH (推荐长期使用)"
    read -p "请选择 (1/2): " auth_method
    
    if [ "$auth_method" = "2" ]; then
        remote_url="git@github.com:${github_username}/webjc-pro.git"
        echo ""
        echo "📝 SSH模式需要:"
        echo "1. 确保已设置SSH密钥"
        echo "2. 如未设置，请参考: https://docs.github.com/en/authentication/connecting-to-github-with-ssh"
    else
        remote_url="https://github.com/${github_username}/webjc-pro.git"
    fi
    
    echo ""
    read -p "确认添加远程仓库: $remote_url (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        git remote add origin $remote_url
        echo "✅ 远程仓库已添加"
    else
        echo "❌ 已取消操作"
        exit 0
    fi
fi

echo ""
echo "========================================="
echo "准备推送到GitHub"
echo "========================================="
echo ""

# 检查是否有未提交的更改
if [ -n "$(git status --porcelain)" ]; then
    read -p "📝 检测到未提交的更改，是否先提交? (y/n): " commit_changes
    if [ "$commit_changes" = "y" ]; then
        read -p "提交信息: " commit_message
        if [ -z "$commit_message" ]; then
            commit_message="Update: $(date '+%Y-%m-%d %H:%M:%S')"
        fi
        git add .
        git commit -m "$commit_message"
        echo "✅ 更改已提交"
    fi
fi

echo ""
read -p "🚀 是否现在推送到GitHub? (y/n): " push_now

if [ "$push_now" = "y" ]; then
    echo ""
    echo "推送中..."
    echo ""
    
    # 推送所有分支和标签
    git push -u origin master --tags
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "========================================="
        echo "✅ 推送成功!"
        echo "========================================="
        echo ""
        
        # 获取远程URL
        remote_url=$(git remote get-url origin)
        
        echo "📦 你的仓库地址:"
        echo "$remote_url"
        echo ""
        
        # 转换为GitHub网页链接
        if [[ $remote_url == *"github.com"* ]]; then
            # 提取用户名和仓库名
            if [[ $remote_url == git@* ]]; then
                web_url="https://github.com/${remote_url#git@github.com:}"
                web_url="${web_url%.git}"
            else
                web_url=$remote_url
            fi
            
            echo "🌐 GitHub页面:"
            echo "$web_url"
            echo ""
            echo "📊 Release页面:"
            echo "${web_url}/releases/tag/v3.0.0"
            echo ""
        fi
        
        echo "========================================="
        echo "🎉 完成！"
        echo "========================================="
        echo ""
        echo "下一步:"
        echo "1. 打开你的GitHub仓库查看文件"
        echo "2. 检查README是否正确渲染"
        echo "3. 创建GitHub Release（可选）"
        echo "4. 更新仓库Topics和描述"
        echo ""
        
    else
        echo ""
        echo "========================================="
        echo "❌ 推送失败"
        echo "========================================="
        echo ""
        echo "常见问题排查:"
        echo ""
        echo "1. 认证失败:"
        echo "   - 使用GitHub CLI: gh auth login"
        echo "   - 或检查用户名/密码/token"
        echo ""
        echo "2. 远程仓库不存在:"
        echo "   - 在GitHub上创建仓库: https://github.com/new"
        echo "   - 仓库名: webjc-pro"
        echo ""
        echo "3. 冲突:"
        echo "   git pull origin master --rebase"
        echo "   git push origin master --tags"
        echo ""
        echo "详细指南请查看: GITHUB_UPLOAD_GUIDE.md"
        echo ""
    fi
else
    echo ""
    echo "已取消推送"
    echo ""
    echo "手动推送命令:"
    echo "  git push -u origin master --tags"
    echo ""
fi

echo "========================================="
echo "Git信息汇总"
echo "========================================="
echo ""
echo "📊 提交数量: $(git rev-list --all --count)"
echo "🏷️  标签数量: $(git tag -l | wc -l)"
echo "📁 文件数量: $(git ls-files | wc -l)"
echo "💾 代码行数: $(git ls-files '*.py' | xargs cat 2>/dev/null | wc -l)"
echo ""
echo "📝 提交历史:"
git log --oneline --all
echo ""
echo "🏷️  标签列表:"
git tag -l
echo ""

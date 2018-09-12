package io.renren.modules.apiAuth;

import io.renren.common.utils.R;
import io.renren.modules.sys.dao.SysUserDao;
import io.renren.modules.sys.entity.SysUserEntity;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <p>Title: AuthPermission</p>
 * <p>Description: </p>
 *  第三方服务请求后台管理系统
 *  1.判断是否存在session  不存在则登录
 *  2.存在则返回是否有访问对应url的权限
 * @Author yangtao
 * @Date 2018/9/4 16:33
 */
@RestController
@RequestMapping(value = "/sys")
public class AuthPermission {

    Logger logger = LoggerFactory.getLogger(AuthPermission.class);

    @Autowired
    private SysUserDao sysUserDao;

    @RequestMapping(value = "/auth", method = RequestMethod.POST)
    public R getAuth(HttpServletRequest request, String requestUrl) {
        //定义list集合存储url
        List<String> urlList = null;
        //判断用户是否登录
        HttpSession session = request.getSession();
        if (session != null) {
            //用户如果登录 获取用户通过shiro授权时候存储的用户对象
            SysUserEntity sysUser = (SysUserEntity) SecurityUtils.getSubject().getPrincipal();
            // 根据获取到的用户信息查询出用户配置的所有URL
            urlList = sysUserDao.queryAllUrl(sysUser.getUserId());
        }else{
            logger.error("Login is invalid, please login again");
            return R.error("登录失效，请先登录！");
        }

        //用户Url列表 将用户Url存储在set集合中（去掉重复，忽略空的Url）
        Set<String> permsSet = new HashSet<>();
        for (String url : urlList) {
            if (StringUtils.isBlank(url)) {
                continue;
            }
            permsSet.addAll(Arrays.asList(url.trim().split(",")));
        }
        //遍历获取的url集合 返回对应的状态
        for (String url : permsSet) {
            if (url.contains(requestUrl)) {
                return R.ok();
            }
        }
        logger.error("No access is allowed, please contact the system administrator.");
        return R.error("没有权限访问，请联系系统管理员！");
    }
}



